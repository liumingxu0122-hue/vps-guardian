#!/bin/sh
set -eu

purge_state=false
if [ "${1:-}" = "--purge-local-state" ]; then
  purge_state=true
  shift
fi
[ "$#" -eq 0 ] || { echo "usage: $0 [--purge-local-state]" >&2; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "helper uninstall must run as root" >&2; exit 77; }

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/var/backups/vps-guardian-agent/net-helper-uninstall-$timestamp"
install -d -o root -g root -m 0700 "$backup"
for path in \
  /usr/local/libexec/vps-guardian-net-helper \
  /etc/systemd/system/vps-guardian-net-helper.socket \
  /etc/systemd/system/vps-guardian-net-helper@.service \
  /var/lib/vps-guardian-net-helper/policies.json; do
  [ ! -e "$path" ] || cp -a "$path" "$backup/"
done
find "$backup" -type f ! -name SHA256SUMS -exec sha256sum {} \; > "$backup/SHA256SUMS"

if [ -x /usr/local/libexec/vps-guardian-net-helper ]; then
  /usr/local/libexec/vps-guardian-net-helper --purge-owned-state
fi
systemctl disable --now vps-guardian-net-helper.socket >/dev/null 2>&1 || true
rm -f /etc/systemd/system/vps-guardian-net-helper.socket
rm -f /etc/systemd/system/vps-guardian-net-helper@.service
rm -f /usr/local/libexec/vps-guardian-net-helper
systemctl daemon-reload

if [ "$purge_state" = true ]; then
  rm -rf -- /var/lib/vps-guardian-net-helper
else
  echo "helper state preserved in /var/lib/vps-guardian-net-helper"
fi
echo "Controller traffic history and append-only reset events were not modified"
echo "uninstall backup: $backup"
