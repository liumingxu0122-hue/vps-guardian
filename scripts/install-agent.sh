#!/bin/sh
set -eu

controller_url=''
host_id=''
enrollment_token_file=''
release_version=''
os_family=''
agent_url_amd64=''
agent_sha256_amd64=''
agent_url_arm64=''
agent_sha256_arm64=''
server_ca_url=''
server_ca_sha256=''
controller_public_key_url=''
controller_public_key_sha256=''
release_manifest_url=''
release_manifest_signature_url=''
release_signing_public_key_url=''
release_signing_public_key_sha256=''

while [ "$#" -gt 0 ]; do
  case "$1" in
    --controller-url) controller_url="$2"; shift 2 ;;
    --host-id) host_id="$2"; shift 2 ;;
    --enrollment-token-file) enrollment_token_file="$2"; shift 2 ;;
    --release-version) release_version="$2"; shift 2 ;;
    --os-family) os_family="$2"; shift 2 ;;
    --agent-url-amd64) agent_url_amd64="$2"; shift 2 ;;
    --agent-sha256-amd64) agent_sha256_amd64="$2"; shift 2 ;;
    --agent-url-arm64) agent_url_arm64="$2"; shift 2 ;;
    --agent-sha256-arm64) agent_sha256_arm64="$2"; shift 2 ;;
    --server-ca-url) server_ca_url="$2"; shift 2 ;;
    --server-ca-sha256) server_ca_sha256="$2"; shift 2 ;;
    --controller-public-key-url) controller_public_key_url="$2"; shift 2 ;;
    --controller-public-key-sha256) controller_public_key_sha256="$2"; shift 2 ;;
    --release-manifest-url) release_manifest_url="$2"; shift 2 ;;
    --release-manifest-signature-url) release_manifest_signature_url="$2"; shift 2 ;;
    --release-signing-public-key-url) release_signing_public_key_url="$2"; shift 2 ;;
    --release-signing-public-key-sha256) release_signing_public_key_sha256="$2"; shift 2 ;;
    *) echo "unknown option" >&2; exit 64 ;;
  esac
done

for value in "$controller_url" "$host_id" "$enrollment_token_file" "$release_version" "$os_family" \
  "$agent_url_amd64" "$agent_sha256_amd64" "$agent_url_arm64" "$agent_sha256_arm64" \
  "$server_ca_url" "$server_ca_sha256" "$controller_public_key_url" \
  "$controller_public_key_sha256" "$release_manifest_url" \
  "$release_manifest_signature_url" "$release_signing_public_key_url" \
  "$release_signing_public_key_sha256"; do
  [ -n "$value" ] || { echo "required installation option is missing" >&2; exit 64; }
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Agent installation must run as root" >&2
  exit 77
fi

case "$controller_url" in https://*) ;; *) echo "Controller URL must use HTTPS" >&2; exit 64 ;; esac
for url in "$agent_url_amd64" "$agent_url_arm64" "$server_ca_url" \
  "$controller_public_key_url" "$release_manifest_url" \
  "$release_manifest_signature_url" "$release_signing_public_key_url"; do
  case "$url" in
    https://*) ;;
    *) echo "all download URLs must use HTTPS" >&2; exit 64 ;;
  esac
  case "$url" in
    *'?'*|*'#'*|*'@'*) echo "download URLs cannot contain credentials, query, or fragment" >&2; exit 64 ;;
  esac
done
case "$release_version" in
  latest|*latest*) echo "latest releases are forbidden" >&2; exit 64 ;;
  v[A-Za-z0-9._-]*) ;;
  *) echo "release version is invalid" >&2; exit 64 ;;
esac
case "$host_id" in
  ????????-????-????-????-????????????) ;;
  *) echo "host ID must be a UUID" >&2; exit 64 ;;
esac
for existing_config_directory in /etc/vps-guardian/agent /etc/vps-guardian-agent; do
  if [ -e "$existing_config_directory" ]; then
    if [ ! -d "$existing_config_directory" ] || [ -L "$existing_config_directory" ]; then
      echo "existing Agent configuration path is unsafe" >&2
      exit 73
    fi
    if [ ! -f "$existing_config_directory/config.json" ] ||
      ! grep -F '"agent_id"' "$existing_config_directory/config.json" >/dev/null 2>&1; then
        echo "existing configuration is not recognized as VPS Guardian Agent; refusing overwrite" >&2
        exit 73
    fi
  fi
done
for digest in "$agent_sha256_amd64" "$agent_sha256_arm64" "$server_ca_sha256" \
  "$controller_public_key_sha256" "$release_signing_public_key_sha256"; do
  case "$digest" in
    *[!a-f0-9]*|'') echo "SHA-256 value is invalid" >&2; exit 64 ;;
  esac
  [ "${#digest}" -eq 64 ] || { echo "SHA-256 value is invalid" >&2; exit 64; }
done

for command in curl sha256sum openssl install mv cp rm chmod chown id getent date mktemp \
  uname grep sed tr head dirname find ln sort base64 wc; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing prerequisite: $command" >&2
    exit 69
  }
done
if [ ! -f /etc/os-release ] || [ -L /etc/os-release ]; then
  echo "Linux distribution metadata is missing or unsafe" >&2
  exit 69
fi
detected_os="$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"'\'' ' | tr '[:upper:]' '[:lower:]')"
case "$os_family:$detected_os" in
  auto:ubuntu|auto:debian|auto:rocky|auto:almalinux|auto:rhel|auto:fedora|auto:alpine) ;;
  debian:ubuntu|debian:debian) ;;
  rhel:rocky|rhel:almalinux|rhel:rhel) ;;
  fedora:fedora) ;;
  alpine:alpine) ;;
  generic:?*) ;;
  *) echo "the detected Linux distribution does not match the enrollment request" >&2; exit 69 ;;
esac
if ! command -v systemctl >/dev/null 2>&1 && ! command -v rc-service >/dev/null 2>&1; then
  echo "systemd or OpenRC is required" >&2
  exit 69
fi
if ! command -v useradd >/dev/null 2>&1 && ! command -v adduser >/dev/null 2>&1; then
  echo "a supported system-user command is required" >&2
  exit 69
fi

case "$(uname -m)" in
  x86_64|amd64)
    agent_url="$agent_url_amd64"
    agent_sha256="$agent_sha256_amd64"
    ;;
  aarch64|arm64)
    agent_url="$agent_url_arm64"
    agent_sha256="$agent_sha256_arm64"
    ;;
  *)
    echo "unsupported CPU architecture" >&2
    exit 69
    ;;
esac

if [ ! -f "$enrollment_token_file" ] || [ -L "$enrollment_token_file" ]; then
  echo "enrollment token file is missing or unsafe" >&2
  exit 65
fi
chmod 0600 "$enrollment_token_file"

work_directory="$(mktemp -d)"
chmod 0700 "$work_directory"
header_file="$work_directory/enrollment-header"
rollback_root="/var/backups/vps-guardian-agent"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$rollback_root"
backup_directory="$(mktemp -d "$rollback_root/install-$timestamp-XXXXXX")"
chmod 0700 "$backup_directory"
install_started=false
old_service_active=false
old_service_enabled=false
old_openrc_started=false
created_user=false
created_group=false
failure_step="initialization"

cleanup() {
  rm -rf -- "$work_directory"
  rm -f -- "$enrollment_token_file"
}

rollback() {
  status="$?"
  [ "$status" -ne 0 ] || return 0
  if [ "$install_started" = true ]; then
    if command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now vps-guardian-agent.service >/dev/null 2>&1 || true
    else
      rc-service vps-guardian-agent stop >/dev/null 2>&1 || true
      rc-update del vps-guardian-agent default >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/vps-guardian-agent.service /etc/init.d/vps-guardian-agent
    rm -f /usr/local/sbin/vps-guardian-agent
    rm -rf /etc/vps-guardian/agent
    rmdir /etc/vps-guardian >/dev/null 2>&1 || true
    if [ -d "$backup_directory/previous" ]; then
      cp -a "$backup_directory/previous/." /
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload >/dev/null 2>&1 || true
      if [ "$old_service_enabled" = true ]; then
        systemctl enable vps-guardian-agent.service >/dev/null 2>&1 || true
      fi
      if [ "$old_service_active" = true ]; then
        systemctl start vps-guardian-agent.service >/dev/null 2>&1 || true
      fi
    elif [ "$old_openrc_started" = true ]; then
      rc-update add vps-guardian-agent default >/dev/null 2>&1 || true
      rc-service vps-guardian-agent start >/dev/null 2>&1 || true
    fi
    if [ "$created_user" = true ]; then
      if command -v userdel >/dev/null 2>&1; then userdel vps-guardian-agent >/dev/null 2>&1 || true
      else deluser vps-guardian-agent >/dev/null 2>&1 || true; fi
    fi
    if [ "$created_group" = true ]; then
      if command -v groupdel >/dev/null 2>&1; then groupdel vps-guardian-agent >/dev/null 2>&1 || true
      else delgroup vps-guardian-agent >/dev/null 2>&1 || true; fi
    fi
  fi
  if command -v report_failure >/dev/null 2>&1; then
    report_failure "$failure_step" true || true
  fi
  cleanup
  echo "Agent installation failed; prior VPS Guardian files and service state were restored" >&2
  exit "$status"
}
trap rollback EXIT

failure_step="release manifest verification"
curl --fail --show-error --location --proto '=https' \
  --connect-timeout 10 --max-time 60 \
  -o "$work_directory/release-manifest" "$release_manifest_url"
curl --fail --show-error --location --proto '=https' \
  --connect-timeout 10 --max-time 60 \
  -o "$work_directory/release-manifest.sig" "$release_manifest_signature_url"
curl --fail --show-error --location --proto '=https' \
  --connect-timeout 10 --max-time 60 \
  -o "$work_directory/release-signing-public-key.pem" "$release_signing_public_key_url"
printf '%s  %s\n' "$release_signing_public_key_sha256" \
  "$work_directory/release-signing-public-key.pem" | sha256sum --check --status || {
    echo "release signing public key checksum mismatch" >&2
    exit 65
  }
openssl pkeyutl -verify -pubin -inkey "$work_directory/release-signing-public-key.pem" \
  -rawin -in "$work_directory/release-manifest" \
  -sigfile "$work_directory/release-manifest.sig" >/dev/null 2>&1 || {
    echo "release manifest signature verification failed" >&2
    exit 65
  }
manifest_version="$(sed -n 's/^version=//p' "$work_directory/release-manifest")"
[ "$manifest_version" = "$release_version" ] || {
  echo "signed release manifest version mismatch or replay detected" >&2
  exit 65
}
manifest_amd64="$(sed -n 's/^sha256_linux_amd64=//p' "$work_directory/release-manifest")"
manifest_arm64="$(sed -n 's/^sha256_linux_arm64=//p' "$work_directory/release-manifest")"
manifest_installer="$(sed -n 's/^sha256_install_agent=//p' "$work_directory/release-manifest")"
[ -f "$0" ] && [ ! -L "$0" ] || exit 65
actual_installer="$(sha256sum "$0" | sed 's/ .*//')"
[ "$manifest_installer" = "$actual_installer" ] || {
  echo "signed release manifest does not match this installer" >&2
  exit 65
}
if [ "$manifest_amd64" != "$agent_sha256_amd64" ] ||
  [ "$manifest_arm64" != "$agent_sha256_arm64" ]; then
    echo "signed release manifest does not match Controller-pinned checksums" >&2
    exit 65
fi
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

enrollment_token="$(cat "$enrollment_token_file")"
case "$enrollment_token" in
  *[!A-Za-z0-9._~-]*|'') echo "enrollment token format is invalid" >&2; exit 65 ;;
esac
if [ "${#enrollment_token}" -lt 32 ] || [ "${#enrollment_token}" -gt 512 ]; then
  echo "enrollment token length is invalid" >&2
  exit 65
fi
printf 'X-Enrollment-Token: %s\n' "$enrollment_token" > "$header_file"
chmod 0600 "$header_file"
unset enrollment_token

report_progress() {
  progress="$1"
  curl --fail --show-error --silent --proto '=https' \
    --connect-timeout 10 --max-time 30 \
    -H 'Content-Type: application/json' -H "@$header_file" \
    --data "{\"status\":\"$progress\"}" \
    "${controller_url%/}/api/v1/agents/enrollment-progress" >/dev/null
}

report_failure() {
  failed_step="$1"
  was_rolled_back="$2"
  curl --fail --show-error --silent --proto '=https' \
    --connect-timeout 10 --max-time 30 \
    -H 'Content-Type: application/json' -H "@$header_file" \
    --data "{\"status\":\"failed\",\"error_code\":\"installer_failed\",\"error_summary\":\"Agent installation failed during $failed_step\",\"rolled_back\":$was_rolled_back}" \
    "${controller_url%/}/api/v1/agents/enrollment-progress" >/dev/null
}

# The outer one-line command downloaded and verified this installer before execution.
failure_step="installer verification"
report_progress installer_downloaded
report_progress installer_verified
report_progress prerequisites_checked

failure_step="Agent download"
curl --fail --show-error --silent --location --proto '=https' \
  --connect-timeout 10 --max-time 180 -o "$work_directory/agent" "$agent_url"
report_progress agent_downloaded
printf '%s  %s\n' "$agent_sha256" "$work_directory/agent" | \
  sha256sum --check --status || {
    echo "Agent binary checksum verification failed" >&2
    exit 65
  }
chmod 0755 "$work_directory/agent"
"$work_directory/agent" version | grep -F "version=${release_version#v}" >/dev/null || {
  echo "Agent binary version does not match the fixed release" >&2
  exit 65
}
report_progress agent_verified

failure_step="Controller trust download"
curl --fail --show-error --silent --location --proto '=https' \
  --connect-timeout 10 --max-time 60 -o "$work_directory/controller-ca.crt" "$server_ca_url"
printf '%s  %s\n' "$server_ca_sha256" "$work_directory/controller-ca.crt" | \
  sha256sum --check --status || {
    echo "Controller CA checksum verification failed" >&2
    exit 65
  }
curl --fail --show-error --silent --location --proto '=https' \
  --connect-timeout 10 --max-time 60 \
  -o "$work_directory/controller-public-key.txt" "$controller_public_key_url"
printf '%s  %s\n' "$controller_public_key_sha256" \
  "$work_directory/controller-public-key.txt" | sha256sum --check --status || {
    echo "Controller public key checksum verification failed" >&2
    exit 65
  }

identity_directory="$work_directory/identity"
failure_step="local identity bootstrap"
"$work_directory/agent" bootstrap \
  --controller-url "$controller_url" \
  --host-id "$host_id" \
  --token-file "$enrollment_token_file" \
  --server-ca-file "$work_directory/controller-ca.crt" \
  --output-dir "$identity_directory" \
  --agent-version "${release_version#v}" \
  --timeout 45s
progress_token="$(cat "$identity_directory/enrollment-progress-token")"
case "$progress_token" in
  *[!A-Za-z0-9._~-]*|'') echo "progress credential format is invalid" >&2; exit 65 ;;
esac
if [ "${#progress_token}" -lt 32 ] || [ "${#progress_token}" -gt 512 ]; then
  echo "progress credential length is invalid" >&2
  exit 65
fi
printf 'X-Enrollment-Progress-Token: %s\n' "$progress_token" > "$header_file"
unset progress_token
rm -f "$enrollment_token_file" "$identity_directory/enrollment-progress-token"

agent_id="$(sed -n 's/.*"agent_id":"\([^"]*\)".*/\1/p' "$identity_directory/bootstrap.json")"
gateway_url="$(sed -n 's/.*"agent_gateway_endpoint":"\([^"]*\)".*/\1/p' \
  "$identity_directory/bootstrap.json")"
controller_public_key="$(tr -d '\r\n' < "$work_directory/controller-public-key.txt")"
case "$agent_id" in
  ????????-????-????-????-????????????) ;;
  *) echo "bootstrap metadata has an invalid Agent ID" >&2; exit 65 ;;
esac
case "$gateway_url" in https://*) ;; *) echo "bootstrap metadata has an invalid gateway URL" >&2; exit 65 ;; esac
case "$controller_public_key" in
  *[!A-Za-z0-9+/=]*|'') echo "Controller public key is invalid" >&2; exit 65 ;;
esac
[ "$(printf '%s' "$controller_public_key" | base64 -d 2>/dev/null | wc -c | tr -d ' ')" -eq 32 ] || {
  echo "Controller public key is invalid" >&2
  exit 65
}

install -d -m 0700 "$backup_directory/previous"
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet vps-guardian-agent.service; then
    old_service_active=true
  fi
  if systemctl is-enabled --quiet vps-guardian-agent.service; then
    old_service_enabled=true
  fi
else
  if rc-service vps-guardian-agent status >/dev/null 2>&1; then
    old_openrc_started=true
  fi
fi
for existing in \
  usr/local/sbin/vps-guardian-agent \
  etc/vps-guardian/agent \
  etc/vps-guardian-agent \
  etc/systemd/system/vps-guardian-agent.service \
  etc/init.d/vps-guardian-agent; do
  if [ -e "/$existing" ] || [ -L "/$existing" ]; then
    install -d -m 0700 "$backup_directory/previous/$(dirname "$existing")"
    cp -a "/$existing" "$backup_directory/previous/$existing"
  fi
done
(cd "$backup_directory" &&
  find . -type f -exec sha256sum {} \; | sort) > "$work_directory/SHA256SUMS"
install -m 0600 "$work_directory/SHA256SUMS" "$backup_directory/SHA256SUMS"

install_started=true
failure_step="service account creation"
if ! getent group vps-guardian-agent >/dev/null 2>&1; then
  if command -v groupadd >/dev/null 2>&1; then
    groupadd --system vps-guardian-agent
  else
    addgroup -S vps-guardian-agent
  fi
  created_group=true
fi
if ! id vps-guardian-agent >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --gid vps-guardian-agent --home-dir /var/lib/vps-guardian/agent \
      --shell /usr/sbin/nologin vps-guardian-agent
  else
    adduser -S -D -H -h /var/lib/vps-guardian/agent -s /sbin/nologin \
      -G vps-guardian-agent vps-guardian-agent
  fi
  created_user=true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop vps-guardian-agent.service >/dev/null 2>&1 || true
else
  rc-service vps-guardian-agent stop >/dev/null 2>&1 || true
fi

install -d -o root -g vps-guardian-agent -m 0750 \
  /etc/vps-guardian /etc/vps-guardian/agent /etc/vps-guardian/agent/trust
install -d -o vps-guardian-agent -g vps-guardian-agent -m 0700 \
  /etc/vps-guardian/agent/identities /var/lib/vps-guardian/agent /var/log/vps-guardian
generation="/etc/vps-guardian/agent/identities/generation-1"
install -d -o vps-guardian-agent -g vps-guardian-agent -m 0700 "$generation"
install -o root -g root -m 0755 "$work_directory/agent" /usr/local/sbin/vps-guardian-agent
install -o vps-guardian-agent -g vps-guardian-agent -m 0600 \
  "$identity_directory/agent.key" "$generation/agent.key"
install -o vps-guardian-agent -g vps-guardian-agent -m 0600 \
  "$identity_directory/signing-ed25519.pem" "$generation/signing-ed25519.pem"
install -o root -g vps-guardian-agent -m 0640 \
  "$identity_directory/agent.crt" "$generation/agent.crt"
install -o root -g vps-guardian-agent -m 0640 \
  "$identity_directory/agent-ca.crt" /etc/vps-guardian/agent/trust/agent-ca.crt
install -o root -g vps-guardian-agent -m 0640 \
  "$work_directory/controller-ca.crt" /etc/vps-guardian/agent/trust/controller-ca.crt
rm -f /etc/vps-guardian/agent/identities/.current-install
ln -s generation-1 /etc/vps-guardian/agent/identities/.current-install
mv -f /etc/vps-guardian/agent/identities/.current-install \
  /etc/vps-guardian/agent/identities/current

cat > /etc/vps-guardian/agent/config.json <<EOF
{"controller_url":"$gateway_url","agent_id":"$agent_id","certificate_file":"/etc/vps-guardian/agent/identities/current/agent.crt","private_key_file":"/etc/vps-guardian/agent/identities/current/agent.key","ca_file":"/etc/vps-guardian/agent/trust/controller-ca.crt","agent_ca_file":"/etc/vps-guardian/agent/trust/agent-ca.crt","signing_key_file":"/etc/vps-guardian/agent/identities/current/signing-ed25519.pem","controller_public_key":"$controller_public_key","certificate_fingerprint":"","queue_file":"/var/lib/vps-guardian/agent/events.jsonl","state_file":"/var/lib/vps-guardian/agent/action-state.json","heartbeat_interval":"30s","certificate_renew_before":"168h","command_timeout":"20s","max_queue_bytes":5242880,"disk_path":"/","systemd_allowlist":[],"container_allowlist":[],"config_allowlist":[],"cache_allowlist":[],"cache_retention":"24h","caddy_container":"","caddy_container_config":"","snapshot_directory":"/var/lib/vps-guardian/agent/snapshots","action_backup_directory":"/var/lib/vps-guardian/agent/action-backups","port_traffic_enabled":false,"net_helper_socket":"","local_health_urls":[],"probe_targets":[],"restic_repository_file":"","restic_password_file":"","restic_paths_allowlist":[]}
EOF
chown root:vps-guardian-agent /etc/vps-guardian/agent/config.json
chmod 0640 /etc/vps-guardian/agent/config.json

failure_step="service installation"
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/vps-guardian-agent.service <<'EOF'
[Unit]
Description=VPS Guardian outbound monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vps-guardian-agent
Group=vps-guardian-agent
ExecStart=/usr/local/sbin/vps-guardian-agent --config /etc/vps-guardian/agent/config.json
Restart=on-failure
RestartSec=10s
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=/var/lib/vps-guardian/agent /var/log/vps-guardian /etc/vps-guardian/agent/identities
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 /etc/systemd/system/vps-guardian-agent.service
  systemctl daemon-reload
  report_progress service_installed
  failure_step="service startup"
  systemctl enable --now vps-guardian-agent.service
  systemctl is-active --quiet vps-guardian-agent.service
  report_progress service_started
else
  cat > /etc/init.d/vps-guardian-agent <<'EOF'
#!/sbin/openrc-run
name="VPS Guardian Agent"
description="VPS Guardian outbound monitoring agent"
command="/usr/local/sbin/vps-guardian-agent"
command_args="--config /etc/vps-guardian/agent/config.json"
command_user="vps-guardian-agent:vps-guardian-agent"
supervisor="supervise-daemon"
pidfile="/run/vps-guardian-agent.pid"
output_log="/var/log/vps-guardian/agent.log"
error_log="/var/log/vps-guardian/agent.log"
respawn_delay=10
respawn_max=0
depend() {
  need net
}
EOF
  chmod 0755 /etc/init.d/vps-guardian-agent
  report_progress service_installed
  failure_step="service startup"
  rc-update add vps-guardian-agent default
  rc-service vps-guardian-agent start
  rc-service vps-guardian-agent status >/dev/null
  report_progress service_started
fi

cleanup
trap - EXIT HUP INT TERM
echo "VPS Guardian Agent installed; enrollment will complete after authenticated heartbeat"
