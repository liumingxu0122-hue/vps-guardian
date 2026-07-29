#!/bin/sh
set -eu
umask 077

controller_url=''
host_id=''
token_file=''
mode=''
release_version=''
expected_identity_version=''
agent_url_amd64=''
agent_sha256_amd64=''
agent_url_arm64=''
agent_sha256_arm64=''
manifest_url=''
manifest_signature_url=''
signing_key_url=''
signing_key_sha256=''
purge_local_state=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --controller-url) controller_url="$2"; shift 2 ;;
    --host-id) host_id="$2"; shift 2 ;;
    --maintenance-token-file) token_file="$2"; shift 2 ;;
    --mode) mode="$2"; shift 2 ;;
    --release-version) release_version="$2"; shift 2 ;;
    --expected-identity-version) expected_identity_version="$2"; shift 2 ;;
    --agent-url-amd64) agent_url_amd64="$2"; shift 2 ;;
    --agent-sha256-amd64) agent_sha256_amd64="$2"; shift 2 ;;
    --agent-url-arm64) agent_url_arm64="$2"; shift 2 ;;
    --agent-sha256-arm64) agent_sha256_arm64="$2"; shift 2 ;;
    --release-manifest-url) manifest_url="$2"; shift 2 ;;
    --release-manifest-signature-url) manifest_signature_url="$2"; shift 2 ;;
    --release-signing-public-key-url) signing_key_url="$2"; shift 2 ;;
    --release-signing-public-key-sha256) signing_key_sha256="$2"; shift 2 ;;
    --purge-local-state) purge_local_state=true; shift ;;
    *) echo "unknown maintenance option" >&2; exit 64 ;;
  esac
done

case "$mode" in repair|reinstall|rotate_identity|decommission) ;; *) exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "Agent maintenance must run as root" >&2; exit 77; }
[ -f "$token_file" ] && [ ! -L "$token_file" ] || { echo "unsafe maintenance token file" >&2; exit 65; }
chmod 0600 "$token_file"
case "$controller_url" in https://*) ;; *) exit 64 ;; esac
for url in "$agent_url_amd64" "$agent_url_arm64" "$manifest_url" \
  "$manifest_signature_url" "$signing_key_url"; do
  case "$url" in https://*) ;; *) echo "downloads require HTTPS" >&2; exit 64 ;; esac
  case "$url" in *'?'*|*'#'*|*'@'*) echo "unsafe download URL" >&2; exit 64 ;; esac
done
for command in curl sha256sum openssl mktemp install cp mv rm chmod grep sed uname sleep; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing prerequisite: $command" >&2; exit 69; }
done

work_directory="$(mktemp -d)"
chmod 0700 "$work_directory"
install -d -m 0700 /var/backups/vps-guardian-agent
backup_directory="$(mktemp -d /var/backups/vps-guardian-agent/maintenance-XXXXXXXX)"
chmod 0700 "$backup_directory"
identity_root=/etc/vps-guardian/agent/identities/current
trust_root=/etc/vps-guardian/agent/trust
[ -f "$identity_root/agent.crt" ] && [ -f "$identity_root/agent.key" ] &&
  [ -f "$trust_root/controller-ca.crt" ] || {
    echo "current Agent mTLS identity is unavailable" >&2
    exit 65
  }
cp "$identity_root/agent.crt" "$work_directory/agent.crt"
cp "$identity_root/agent.key" "$work_directory/agent.key"
cp "$trust_root/controller-ca.crt" "$work_directory/controller-ca.crt"
chmod 0600 "$work_directory/agent.key"
progress_token=''
service_was_active=false
changes_started=false

cleanup() {
  rm -rf -- "$work_directory"
  rm -f -- "$token_file"
  progress_token=''
}

report() {
  status_value="$1"
  error_code="${2:-}"
  error_summary="${3:-}"
  rolled_back="${4:-false}"
  [ -n "$progress_token" ] || return 0
  payload="$(printf '{"kind":"%s","status":"%s","error_code":"%s","error_summary":"%s","rolled_back":%s}' \
    "$mode" "$status_value" "$error_code" "$error_summary" "$rolled_back")"
  curl --fail --show-error --proto '=https' --connect-timeout 10 --max-time 30 \
    --cert "$work_directory/agent.crt" --key "$work_directory/agent.key" \
    --cacert "$work_directory/controller-ca.crt" \
    -H "Content-Type: application/json" -H "X-Maintenance-Progress: $progress_token" \
    --data "$payload" "$controller_url/api/v1/agents/maintenance/progress" >/dev/null
}

service_stop() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet vps-guardian-agent.service && service_was_active=true || true
    systemctl stop vps-guardian-agent.service
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service vps-guardian-agent status >/dev/null 2>&1 && service_was_active=true || true
    rc-service vps-guardian-agent stop
  else
    echo "supported service manager not found" >&2
    return 1
  fi
}

service_start() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl start vps-guardian-agent.service
  else
    rc-service vps-guardian-agent start
  fi
}

rollback() {
  status_code="$?"
  if [ "$status_code" -ne 0 ] && [ "$changes_started" = true ] && [ "$mode" != decommission ]; then
    [ ! -f "$backup_directory/agent" ] ||
      install -o root -g root -m 0755 "$backup_directory/agent" /usr/local/sbin/vps-guardian-agent
    if [ -d "$backup_directory/config" ]; then
      rm -rf /etc/vps-guardian/agent
      cp -a "$backup_directory/config" /etc/vps-guardian/agent
    fi
    [ "$service_was_active" = false ] || service_start >/dev/null 2>&1 || true
    report rolled_back maintenance_failed "maintenance failed; prior binary, config, and identity link restored" true || true
  elif [ "$status_code" -ne 0 ]; then
    report failed maintenance_failed "maintenance failed closed" false || true
  fi
  cleanup
  [ "$status_code" -eq 0 ] || exit "$status_code"
}
trap rollback EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

maintenance_token="$(cat "$token_file")"
case "$maintenance_token" in *[!A-Za-z0-9._~-]*|'') exit 65 ;; esac
start_payload="$(printf '{"kind":"%s"}' "$mode")"
start_response="$work_directory/start.json"
curl --fail --show-error --proto '=https' --connect-timeout 10 --max-time 30 \
  --cert "$work_directory/agent.crt" --key "$work_directory/agent.key" \
  --cacert "$work_directory/controller-ca.crt" \
  -H "Content-Type: application/json" -H "X-Maintenance-Token: $maintenance_token" \
  --data "$start_payload" -o "$start_response" \
  "$controller_url/api/v1/agents/maintenance/start"
unset maintenance_token
progress_token="$(sed -n 's/.*"progress_token":"\([^"]*\)".*/\1/p' "$start_response")"
[ -n "$progress_token" ] || { echo "Controller did not issue progress credential" >&2; exit 65; }

curl --fail --show-error --location --proto '=https' -o "$work_directory/manifest" "$manifest_url"
curl --fail --show-error --location --proto '=https' -o "$work_directory/manifest.sig" "$manifest_signature_url"
curl --fail --show-error --location --proto '=https' -o "$work_directory/release-key.pem" "$signing_key_url"
printf '%s  %s\n' "$signing_key_sha256" "$work_directory/release-key.pem" |
  sha256sum --check --status || exit 65
openssl pkeyutl -verify -pubin -inkey "$work_directory/release-key.pem" -rawin \
  -in "$work_directory/manifest" -sigfile "$work_directory/manifest.sig" >/dev/null 2>&1 || exit 65
[ "$(sed -n 's/^version=//p' "$work_directory/manifest")" = "$release_version" ] || exit 65
[ -f "$0" ] && [ ! -L "$0" ] || exit 65
[ "$(sed -n 's/^sha256_maintain_agent=//p' "$work_directory/manifest")" = \
  "$(sha256sum "$0" | sed 's/ .*//')" ] || exit 65
report artifact_verified

case "$(uname -m)" in
  x86_64|amd64) agent_url="$agent_url_amd64"; agent_sha256="$agent_sha256_amd64"; manifest_key=sha256_linux_amd64 ;;
  aarch64|arm64) agent_url="$agent_url_arm64"; agent_sha256="$agent_sha256_arm64"; manifest_key=sha256_linux_arm64 ;;
  *) exit 69 ;;
esac
[ "$(sed -n "s/^$manifest_key=//p" "$work_directory/manifest")" = "$agent_sha256" ] || exit 65

if [ "$mode" = decommission ]; then
  service_stop
  changes_started=true
  report service_stopped
  rm -f /usr/local/sbin/vps-guardian-agent
  rm -f /etc/systemd/system/vps-guardian-agent.service /etc/init.d/vps-guardian-agent
  rm -rf /etc/vps-guardian/agent /etc/vps-guardian-agent
  if [ "$purge_local_state" = true ]; then
    rm -rf /var/lib/vps-guardian-agent
  fi
  report confirmation_pending
  cleanup
  trap - EXIT HUP INT TERM
  echo "Local Agent decommission complete; Controller certificate revocation is pending"
  exit 0
fi

curl --fail --show-error --location --proto '=https' --connect-timeout 10 --max-time 180 \
  -o "$work_directory/agent" "$agent_url"
printf '%s  %s\n' "$agent_sha256" "$work_directory/agent" | sha256sum --check --status
chmod 0755 "$work_directory/agent"
"$work_directory/agent" version | grep -F "version=${release_version#v}" >/dev/null

[ ! -f /usr/local/sbin/vps-guardian-agent ] ||
  cp -p /usr/local/sbin/vps-guardian-agent "$backup_directory/agent"
[ ! -d /etc/vps-guardian/agent ] ||
  cp -a /etc/vps-guardian/agent "$backup_directory/config"
service_stop
changes_started=true
report service_stopped
install -o root -g root -m 0755 "$work_directory/agent" /usr/local/sbin/vps-guardian-agent
if [ "$mode" = reinstall ] || [ "$mode" = rotate_identity ]; then
  /usr/local/sbin/vps-guardian-agent rotate-identity \
    --config /etc/vps-guardian/agent/config.json \
    --expected-version "$expected_identity_version"
  report identity_rotated
fi
service_start
report service_started
heartbeat_attempt=0
until report heartbeat_verified; do
  heartbeat_attempt=$((heartbeat_attempt + 1))
  [ "$heartbeat_attempt" -lt 9 ] || exit 70
  sleep 10
done
if [ "$mode" = repair ]; then
  report completed
else
  report confirmation_pending
fi
cleanup
trap - EXIT HUP INT TERM
echo "Agent maintenance applied; Controller post-check and old-identity revocation remain gated"
