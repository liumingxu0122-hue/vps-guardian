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
backup_dir="/var/backups/vps-guardian-agent/uninstall-$timestamp"
install -d -m 0700 "$backup_dir"
[ ! -e /usr/local/sbin/vps-guardian-agent ] || \
  cp -a /usr/local/sbin/vps-guardian-agent "$backup_dir/agent-binary"
[ ! -e /etc/vps-guardian-agent ] || \
  cp -a /etc/vps-guardian-agent "$backup_dir/etc-vps-guardian-agent"
[ ! -e /etc/systemd/system/vps-guardian-agent.service ] || \
  cp -a /etc/systemd/system/vps-guardian-agent.service "$backup_dir/systemd-service"
find "$backup_dir" -type f -exec sha256sum {} \; > "$backup_dir/SHA256SUMS"

systemctl disable --now vps-guardian-agent.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/vps-guardian-agent.service
rm -f /usr/local/sbin/vps-guardian-agent
rm -rf /etc/vps-guardian-agent
systemctl daemon-reload

if [ "$purge_state" = true ]; then
  rm -rf /var/lib/vps-guardian-agent
  userdel vps-guardian-agent >/dev/null 2>&1 || true
  groupdel vps-guardian-agent >/dev/null 2>&1 || true
else
  echo 'Local queue and state were preserved in /var/lib/vps-guardian-agent'
fi
echo "Controller-side host history and audit records were not modified"
echo "Uninstall backup: $backup_dir"
