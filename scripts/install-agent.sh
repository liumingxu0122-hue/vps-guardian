#!/bin/sh
set -eu

binary=''
expected_sha256=''
controller_url=''
agent_name=''
agent_address=''
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
for command in curl jq openssl sha256sum systemctl getent groupadd useradd usermod install; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 69; }
done
for value in "$binary" "$expected_sha256" "$controller_url" "$agent_name" "$agent_address" \
  "$certificate" "$private_key" "$agent_ca" "$server_ca" "$signing_key" \
  "$controller_public_key" "$enrollment_token_file"; do
  [ -n "$value" ] || { echo "all installation options are required" >&2; exit 64; }
done
case "$controller_url" in https://*) ;; *) echo "controller URL must use HTTPS" >&2; exit 64 ;; esac
printf '%s  %s\n' "$expected_sha256" "$binary" | sha256sum --check --status || {
  echo "Agent binary checksum mismatch" >&2
  exit 65
}
openssl verify -CAfile "$agent_ca" "$certificate" >/dev/null
openssl x509 -in "$certificate" -noout -checkend 86400 >/dev/null || {
  echo "Agent certificate is expired or expires within 24 hours" >&2
  exit 65
}

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/backups/vps-guardian-agent/$timestamp"
if [ -e /usr/local/sbin/vps-guardian-agent ] || [ -e /etc/vps-guardian-agent/config.json ]; then
  install -d -m 0700 "$backup_dir"
  [ ! -e /usr/local/sbin/vps-guardian-agent ] || cp -a /usr/local/sbin/vps-guardian-agent "$backup_dir/"
  [ ! -e /etc/vps-guardian-agent ] || cp -a /etc/vps-guardian-agent "$backup_dir/"
  find "$backup_dir" -type f -exec sha256sum {} \; > "$backup_dir/SHA256SUMS"
fi

getent group vps-guardian-agent >/dev/null 2>&1 || groupadd --system vps-guardian-agent
id vps-guardian-agent >/dev/null 2>&1 || \
  useradd --system --gid vps-guardian-agent --home-dir /var/lib/vps-guardian-agent \
    --shell /usr/sbin/nologin vps-guardian-agent
getent group docker >/dev/null 2>&1 || { echo 'Docker group is required' >&2; exit 69; }
supplementary='docker'
if getent group systemd-journal >/dev/null 2>&1; then supplementary="$supplementary,systemd-journal"; fi
usermod -a -G "$supplementary" vps-guardian-agent

install -d -o root -g vps-guardian-agent -m 0750 \
  /etc/vps-guardian-agent /etc/vps-guardian-agent/tls
install -d -o vps-guardian-agent -g vps-guardian-agent -m 0700 /var/lib/vps-guardian-agent
install -m 0755 "$binary" /usr/local/sbin/vps-guardian-agent
install -o root -g vps-guardian-agent -m 0640 "$private_key" /etc/vps-guardian-agent/tls/agent.key
install -o root -g vps-guardian-agent -m 0644 "$certificate" /etc/vps-guardian-agent/tls/agent.crt
install -o root -g vps-guardian-agent -m 0644 "$agent_ca" /etc/vps-guardian-agent/tls/agent-ca.crt
install -o root -g vps-guardian-agent -m 0644 "$server_ca" /etc/vps-guardian-agent/tls/controller-ca.crt
install -o root -g vps-guardian-agent -m 0640 "$signing_key" /etc/vps-guardian-agent/signing-ed25519.pem

fingerprint="$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')"
signing_public_key="$(openssl pkey -in "$signing_key" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')"
enrollment_token="$(cat "$enrollment_token_file")"
case "$enrollment_token" in
  *[!A-Za-z0-9._~-]*|'') echo "invalid enrollment token format" >&2; exit 65 ;;
esac
if [ "${#enrollment_token}" -lt 32 ] || [ "${#enrollment_token}" -gt 512 ]; then
  echo "invalid enrollment token length" >&2
  exit 65
fi
payload="$(jq -cn \
  --arg name "$agent_name" --arg address "$agent_address" --arg key "$signing_public_key" \
  --arg fingerprint "$fingerprint" \
  '{host:{name:$name,address:$address,labels:{}},signing_public_key:$key,certificate_fingerprint:$fingerprint,version:"0.1.0"}')"
header_file="$(mktemp)"
trap 'rm -f "$header_file"' EXIT HUP INT TERM
chmod 0600 "$header_file"
printf 'X-Enrollment-Token: %s\n' "$enrollment_token" > "$header_file"
response="$(curl --fail --silent --show-error --cacert "$server_ca" --cert "$certificate" \
  --key "$private_key" -H 'Content-Type: application/json' \
  -H "@$header_file" --data "$payload" \
  "${controller_url%/}/api/v1/agents/enroll")"
unset enrollment_token
rm -f "$header_file"
trap - EXIT HUP INT TERM
agent_id="$(printf '%s' "$response" | jq -er '.agent_id')"

jq -n \
  --arg controller_url "$controller_url" --arg agent_id "$agent_id" \
  --arg controller_public_key "$controller_public_key" --arg fingerprint "$fingerprint" \
  '{controller_url:$controller_url,agent_id:$agent_id,certificate_file:"/etc/vps-guardian-agent/tls/agent.crt",private_key_file:"/etc/vps-guardian-agent/tls/agent.key",ca_file:"/etc/vps-guardian-agent/tls/controller-ca.crt",signing_key_file:"/etc/vps-guardian-agent/signing-ed25519.pem",controller_public_key:$controller_public_key,certificate_fingerprint:$fingerprint,queue_file:"/var/lib/vps-guardian-agent/events.jsonl",state_file:"/var/lib/vps-guardian-agent/action-state.json",heartbeat_interval:"30s",command_timeout:"20s",max_queue_bytes:5242880,disk_path:"/",systemd_allowlist:[],container_allowlist:[],config_allowlist:[],cache_allowlist:[],cache_retention:"24h",caddy_container:"",caddy_container_config:"",snapshot_directory:"/var/lib/vps-guardian-agent/snapshots",action_backup_directory:"/var/lib/vps-guardian-agent/action-backups",local_health_urls:[]}' \
  > /etc/vps-guardian-agent/config.json
chown root:vps-guardian-agent /etc/vps-guardian-agent/config.json
chmod 0640 /etc/vps-guardian-agent/config.json

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
install -m 0644 "$script_dir/../deploy/systemd/vps-guardian-agent.service" /etc/systemd/system/vps-guardian-agent.service
systemctl daemon-reload
systemctl enable --now vps-guardian-agent.service
systemctl --no-pager --full status vps-guardian-agent.service
printf 'Agent enrolled as %s; previous files: %s\n' "$agent_id" "${backup_dir:-none}"
