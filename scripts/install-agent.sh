#!/bin/sh
set -eu

binary=''
expected_sha256=''
controller_url=''
agent_name=''
agent_address=''
host_id=''
certificate=''
private_key=''
agent_ca=''
server_ca=''
signing_key=''
controller_public_key=''
enrollment_token_file=''

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) binary="$2"; shift 2 ;;
    --sha256) expected_sha256="$2"; shift 2 ;;
    --controller-url) controller_url="$2"; shift 2 ;;
    --agent-name) agent_name="$2"; shift 2 ;;
    --agent-address) agent_address="$2"; shift 2 ;;
    --host-id) host_id="$2"; shift 2 ;;
    --certificate) certificate="$2"; shift 2 ;;
    --private-key) private_key="$2"; shift 2 ;;
    --agent-ca) agent_ca="$2"; shift 2 ;;
    --server-ca) server_ca="$2"; shift 2 ;;
    --ca) agent_ca="$2"; server_ca="$2"; shift 2 ;;
    --signing-key) signing_key="$2"; shift 2 ;;
    --controller-public-key) controller_public_key="$2"; shift 2 ;;
    --enrollment-token-file) enrollment_token_file="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Agent installation must run as root" >&2
  exit 77
fi
for command in base64 cut curl jq openssl sha256sum systemctl getent groupadd useradd usermod install ln mv; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 69; }
done
for value in "$binary" "$expected_sha256" "$controller_url" "$server_ca" \
  "$controller_public_key" "$enrollment_token_file"; do
  [ -n "$value" ] || { echo "required installation option is missing" >&2; exit 64; }
done
bootstrap='false'
if [ -n "$host_id" ]; then
  bootstrap='true'
  case "$host_id" in
    ????????-????-????-????-????????????) ;;
    *) echo "host ID must be a UUID" >&2; exit 64 ;;
  esac
else
  for value in "$agent_name" "$agent_address" "$certificate" "$private_key" "$agent_ca" "$signing_key"; do
    [ -n "$value" ] || { echo "legacy installation options are incomplete" >&2; exit 64; }
  done
fi
case "$controller_url" in https://*) ;; *) echo "controller URL must use HTTPS" >&2; exit 64 ;; esac
printf '%s  %s\n' "$expected_sha256" "$binary" | sha256sum --check --status || {
  echo "Agent binary checksum mismatch" >&2
  exit 65
}
[ -f "$server_ca" ] && [ ! -L "$server_ca" ] || {
  echo "Controller CA file is missing or unsafe" >&2
  exit 65
}

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/backups/vps-guardian-agent/$timestamp"
had_binary=false
had_config=false
if [ -e /usr/local/sbin/vps-guardian-agent ] || [ -e /etc/vps-guardian-agent/config.json ]; then
  install -d -m 0700 "$backup_dir"
  if [ -e /usr/local/sbin/vps-guardian-agent ]; then
    had_binary=true
    cp -a /usr/local/sbin/vps-guardian-agent "$backup_dir/agent-binary"
  fi
  if [ -e /etc/vps-guardian-agent ]; then
    had_config=true
    cp -a /etc/vps-guardian-agent "$backup_dir/etc-vps-guardian-agent"
  fi
  find "$backup_dir" -type f -exec sha256sum {} \; > "$backup_dir/SHA256SUMS"
fi

rollback_install() {
  status="$?"
  [ "$status" -ne 0 ] || return 0
  rm -f "${header_file:-}"
  [ -z "${bootstrap_dir:-}" ] || rm -rf "$bootstrap_dir"
  systemctl disable --now vps-guardian-agent.service >/dev/null 2>&1 || true
  if [ -d "$backup_dir" ]; then
    if [ "$had_binary" = true ]; then
      cp -a "$backup_dir/agent-binary" /usr/local/sbin/vps-guardian-agent
    else
      rm -f /usr/local/sbin/vps-guardian-agent
    fi
    if [ "$had_config" = true ]; then
      rm -rf /etc/vps-guardian-agent
      cp -a "$backup_dir/etc-vps-guardian-agent" /etc/vps-guardian-agent
    else
      rm -rf /etc/vps-guardian-agent
    fi
  else
    rm -f /usr/local/sbin/vps-guardian-agent
    rm -rf /etc/vps-guardian-agent
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [ "$had_binary" = true ] && [ "$had_config" = true ]; then
    systemctl enable --now vps-guardian-agent.service >/dev/null 2>&1 || true
  fi
  echo "Agent installation failed; previous installation was restored" >&2
  exit "$status"
}
trap rollback_install EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$bootstrap" = 'true' ]; then
  bootstrap_dir="$(mktemp -d)"
  chmod 0700 "$bootstrap_dir"
  private_key="$bootstrap_dir/agent.key"
  certificate="$bootstrap_dir/agent.crt"
  agent_ca="$bootstrap_dir/agent-ca.crt"
  signing_key="$bootstrap_dir/signing-ed25519.pem"
  csr_file="$bootstrap_dir/agent.csr"
  payload_file="$bootstrap_dir/bootstrap.json"
  response_file="$bootstrap_dir/bootstrap-response.json"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$private_key"
  openssl req -new -sha256 -key "$private_key" -subj "/CN=vps-guardian-bootstrap" \
    -out "$csr_file"
  openssl genpkey -algorithm ED25519 -out "$signing_key"
  signing_public_key="$(openssl pkey -in "$signing_key" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')"
  jq -n --arg host_id "$host_id" --rawfile csr "$csr_file" \
    --arg key "$signing_public_key" \
    '{host_id:$host_id,csr_pem:$csr,signing_public_key:$key,version:"0.1.0-alpha.2"}' \
    > "$payload_file"
  enrollment_token="$(cat "$enrollment_token_file")"
  case "$enrollment_token" in
    *[!A-Za-z0-9._~-]*|'') echo "invalid enrollment token format" >&2; exit 65 ;;
  esac
  if [ "${#enrollment_token}" -lt 32 ] || [ "${#enrollment_token}" -gt 512 ]; then
    echo "invalid enrollment token length" >&2
    exit 65
  fi
  header_file="$(mktemp)"
  chmod 0600 "$header_file"
  printf 'X-Enrollment-Token: %s\n' "$enrollment_token" > "$header_file"
  curl --fail --silent --show-error --cacert "$server_ca" \
    -H 'Content-Type: application/json' -H "@$header_file" --data "@$payload_file" \
    "${controller_url%/}/api/v1/agents/bootstrap" > "$response_file"
  unset enrollment_token
  rm -f "$header_file" "$enrollment_token_file" "$payload_file" "$csr_file"
  header_file=''
  jq -er '.certificate_pem' "$response_file" > "$certificate"
  jq -er '.ca_bundle_pem' "$response_file" > "$agent_ca"
  agent_id="$(jq -er '.agent_id' "$response_file")"
  controller_url="$(jq -er '.agent_gateway_endpoint' "$response_file")"
  rm -f "$response_file"
fi

openssl verify -CAfile "$agent_ca" "$certificate" >/dev/null
openssl x509 -in "$certificate" -noout -checkend 86400 >/dev/null || {
  echo "Agent certificate is expired or expires within 24 hours" >&2
  exit 65
}
certificate_public="$(openssl x509 -in "$certificate" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)"
private_public="$(openssl pkey -in "$private_key" -pubout -outform DER | sha256sum | cut -d' ' -f1)"
[ "$certificate_public" = "$private_public" ] || {
  echo "Agent certificate and local private key do not match" >&2
  exit 65
}

printf '%s\n' 'The installer will modify only:' \
  '  /usr/local/sbin/vps-guardian-agent' \
  '  /etc/vps-guardian-agent/' \
  '  /var/lib/vps-guardian-agent/' \
  '  /etc/systemd/system/vps-guardian-agent.service'

getent group vps-guardian-agent >/dev/null 2>&1 || groupadd --system vps-guardian-agent
id vps-guardian-agent >/dev/null 2>&1 || \
  useradd --system --gid vps-guardian-agent --home-dir /var/lib/vps-guardian-agent \
    --shell /usr/sbin/nologin vps-guardian-agent
supplementary=''
if getent group docker >/dev/null 2>&1; then supplementary='docker'; fi
if getent group systemd-journal >/dev/null 2>&1; then
  if [ -n "$supplementary" ]; then supplementary="$supplementary,systemd-journal"
  else supplementary='systemd-journal'; fi
fi
[ -z "$supplementary" ] || usermod -a -G "$supplementary" vps-guardian-agent

install -d -o root -g vps-guardian-agent -m 0750 \
  /etc/vps-guardian-agent /etc/vps-guardian-agent/trust
install -d -o root -g vps-guardian-agent -m 0770 \
  /etc/vps-guardian-agent/identities
identity_generation='/etc/vps-guardian-agent/identities/generation-1'
install -d -o root -g vps-guardian-agent -m 0750 "$identity_generation"
install -d -o vps-guardian-agent -g vps-guardian-agent -m 0700 /var/lib/vps-guardian-agent
install -m 0755 "$binary" /usr/local/sbin/vps-guardian-agent
install -o root -g vps-guardian-agent -m 0640 "$private_key" "$identity_generation/agent.key"
install -o root -g vps-guardian-agent -m 0644 "$certificate" "$identity_generation/agent.crt"
install -o root -g vps-guardian-agent -m 0640 "$signing_key" "$identity_generation/signing-ed25519.pem"
install -o root -g vps-guardian-agent -m 0644 "$agent_ca" /etc/vps-guardian-agent/trust/agent-ca.crt
install -o root -g vps-guardian-agent -m 0644 "$server_ca" /etc/vps-guardian-agent/trust/controller-ca.crt
current_link='/etc/vps-guardian-agent/identities/current'
next_link='/etc/vps-guardian-agent/identities/.current-install'
rm -f "$next_link"
ln -s 'generation-1' "$next_link"
mv -Tf "$next_link" "$current_link"

fingerprint="$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')"
signing_public_key="$(openssl pkey -in "$signing_key" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')"
if [ "$bootstrap" != 'true' ]; then
  enrollment_token="$(cat "$enrollment_token_file")"
  case "$enrollment_token" in
    *[!A-Za-z0-9._~-]*|'') echo "invalid enrollment token format" >&2; exit 65 ;;
  esac
  payload="$(jq -cn \
    --arg name "$agent_name" --arg address "$agent_address" --arg key "$signing_public_key" \
    --arg fingerprint "$fingerprint" \
    '{host:{name:$name,address:$address,labels:{}},signing_public_key:$key,certificate_fingerprint:$fingerprint,version:"0.1.0"}')"
  header_file="$(mktemp)"
  chmod 0600 "$header_file"
  printf 'X-Enrollment-Token: %s\n' "$enrollment_token" > "$header_file"
  response="$(curl --fail --silent --show-error --cacert "$server_ca" --cert "$certificate" \
    --key "$private_key" -H 'Content-Type: application/json' \
    -H "@$header_file" --data "$payload" \
    "${controller_url%/}/api/v1/agents/enroll")"
  unset enrollment_token
  rm -f "$header_file" "$enrollment_token_file"
  header_file=''
  agent_id="$(printf '%s' "$response" | jq -er '.agent_id')"
fi

jq -n \
  --arg controller_url "$controller_url" --arg agent_id "$agent_id" \
  --arg controller_public_key "$controller_public_key" --arg fingerprint "$fingerprint" \
  '{controller_url:$controller_url,agent_id:$agent_id,certificate_file:"/etc/vps-guardian-agent/identities/current/agent.crt",private_key_file:"/etc/vps-guardian-agent/identities/current/agent.key",ca_file:"/etc/vps-guardian-agent/trust/controller-ca.crt",agent_ca_file:"/etc/vps-guardian-agent/trust/agent-ca.crt",signing_key_file:"/etc/vps-guardian-agent/identities/current/signing-ed25519.pem",controller_public_key:$controller_public_key,certificate_fingerprint:$fingerprint,queue_file:"/var/lib/vps-guardian-agent/events.jsonl",state_file:"/var/lib/vps-guardian-agent/action-state.json",heartbeat_interval:"30s",certificate_renew_before:"168h",command_timeout:"20s",max_queue_bytes:5242880,disk_path:"/",systemd_allowlist:[],container_allowlist:[],config_allowlist:[],cache_allowlist:[],cache_retention:"24h",caddy_container:"",caddy_container_config:"",snapshot_directory:"/var/lib/vps-guardian-agent/snapshots",action_backup_directory:"/var/lib/vps-guardian-agent/action-backups",local_health_urls:[]}' \
  > /etc/vps-guardian-agent/config.json
chown root:vps-guardian-agent /etc/vps-guardian-agent/config.json
chmod 0640 /etc/vps-guardian-agent/config.json

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
install -m 0644 "$script_dir/../deploy/systemd/vps-guardian-agent.service" /etc/systemd/system/vps-guardian-agent.service
systemctl daemon-reload
systemctl enable --now vps-guardian-agent.service
systemctl --no-pager --full status vps-guardian-agent.service
[ -z "${bootstrap_dir:-}" ] || rm -rf "$bootstrap_dir"
bootstrap_dir=''
trap - EXIT HUP INT TERM
printf 'Agent enrolled as %s; previous files: %s\n' "$agent_id" "${backup_dir:-none}"
