#!/bin/sh
set -eu

purge_state=false
if [ "${1:-}" = '--purge-local-state' ]; then
  purge_state=true
  shift
fi
if [ "$#" -ne 0 ]; then
  echo "usage: $0 [--purge-local-state]" >&2
  exit 64
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "Agent uninstall must run as root" >&2
  exit 77
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 /var/backups/vps-guardian-agent
backup_dir="$(mktemp -d "/var/backups/vps-guardian-agent/uninstall-$timestamp-XXXXXX")"
chmod 0700 "$backup_dir"
[ ! -e /usr/local/sbin/vps-guardian-agent ] || \
  cp -a /usr/local/sbin/vps-guardian-agent "$backup_dir/agent-binary"
[ ! -e /etc/vps-guardian-agent ] || \
  cp -a /etc/vps-guardian-agent "$backup_dir/etc-vps-guardian-agent"
[ ! -e /etc/vps-guardian/agent ] || \
  cp -a /etc/vps-guardian/agent "$backup_dir/etc-vps-guardian-agent-current"
[ ! -e /etc/systemd/system/vps-guardian-agent.service ] || \
  cp -a /etc/systemd/system/vps-guardian-agent.service "$backup_dir/systemd-service"
[ ! -e /etc/init.d/vps-guardian-agent ] || \
  cp -a /etc/init.d/vps-guardian-agent "$backup_dir/openrc-service"
find "$backup_dir" -type f ! -name SHA256SUMS -exec sha256sum {} \; > "$backup_dir/SHA256SUMS"

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now vps-guardian-agent.service >/dev/null 2>&1 || true
else
  rc-service vps-guardian-agent stop >/dev/null 2>&1 || true
  rc-update del vps-guardian-agent default >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/system/vps-guardian-agent.service
rm -f /etc/init.d/vps-guardian-agent
rm -f /usr/local/sbin/vps-guardian-agent
rm -rf /etc/vps-guardian-agent
rm -rf /etc/vps-guardian/agent
rmdir /etc/vps-guardian >/dev/null 2>&1 || true
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

if [ "$purge_state" = true ]; then
  rm -rf /var/lib/vps-guardian-agent
  rm -rf /var/lib/vps-guardian/agent /var/log/vps-guardian
  rmdir /var/lib/vps-guardian >/dev/null 2>&1 || true
  userdel vps-guardian-agent >/dev/null 2>&1 || true
  groupdel vps-guardian-agent >/dev/null 2>&1 || true
else
  echo 'Local queue and state were preserved in /var/lib/vps-guardian/agent or the legacy path'
fi
echo "Controller-side host history and audit records were not modified"
echo "Uninstall backup: $backup_dir"
