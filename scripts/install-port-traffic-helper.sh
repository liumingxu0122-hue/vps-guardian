#!/bin/sh
set -eu

usage() {
  echo "usage: $0 --binary PATH --sha256 HEX" >&2
  exit 64
}

binary=''
expected=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) [ "$#" -ge 2 ] || usage; binary=$2; shift 2 ;;
    --sha256) [ "$#" -ge 2 ] || usage; expected=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "helper installation must run as root" >&2; exit 77; }
if [ -z "$binary" ] || [ -z "$expected" ]; then
  usage
fi
case "$expected" in *[!a-f0-9]*|'') echo "sha256 must be lowercase hexadecimal" >&2; exit 65 ;; esac
[ "${#expected}" -eq 64 ] || { echo "sha256 must contain 64 characters" >&2; exit 65; }
if [ ! -f "$binary" ] || [ -L "$binary" ]; then
  echo "helper artifact must be a regular file" >&2
  exit 66
fi
for command in sha256sum install systemctl systemd-analyze nft tc; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 69; }
done
actual="$(sha256sum "$binary" | awk '{print $1}')"
[ "$actual" = "$expected" ] || { echo "helper artifact checksum mismatch" >&2; exit 65; }

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
source_dir="$script_dir/../deploy/systemd"
for name in vps-guardian-net-helper.socket vps-guardian-net-helper@.service; do
  if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
    echo "missing systemd unit: $name" >&2
    exit 66
  fi
done
systemd-analyze verify \
  "$source_dir/vps-guardian-net-helper.socket" \
  "$source_dir/vps-guardian-net-helper@.service"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/var/backups/vps-guardian-agent/net-helper-$timestamp"
previous_socket_enabled=false
previous_socket_active=false
if systemctl is-enabled --quiet vps-guardian-net-helper.socket 2>/dev/null; then
  previous_socket_enabled=true
fi
if systemctl is-active --quiet vps-guardian-net-helper.socket 2>/dev/null; then
  previous_socket_active=true
fi
install -d -o root -g root -m 0700 "$backup"
for path in \
  /usr/local/libexec/vps-guardian-net-helper \
  /etc/systemd/system/vps-guardian-net-helper.socket \
  /etc/systemd/system/vps-guardian-net-helper@.service; do
  [ ! -e "$path" ] || cp -a "$path" "$backup/"
done
find "$backup" -type f ! -name SHA256SUMS -exec sha256sum {} \; > "$backup/SHA256SUMS"

rollback() {
  systemctl disable --now vps-guardian-net-helper.socket >/dev/null 2>&1 || true
  rm -f /usr/local/libexec/vps-guardian-net-helper
  rm -f /etc/systemd/system/vps-guardian-net-helper.socket
  rm -f /etc/systemd/system/vps-guardian-net-helper@.service
  for name in vps-guardian-net-helper vps-guardian-net-helper.socket vps-guardian-net-helper@.service; do
    [ ! -e "$backup/$name" ] || case "$name" in
      vps-guardian-net-helper)
        install -o root -g root -m 0755 "$backup/$name" /usr/local/libexec/vps-guardian-net-helper
        ;;
      *)
        install -o root -g root -m 0644 "$backup/$name" "/etc/systemd/system/$name"
        ;;
    esac
  done
  systemctl daemon-reload
  if "$previous_socket_enabled"; then
    systemctl enable vps-guardian-net-helper.socket >/dev/null 2>&1 || true
  fi
  if "$previous_socket_active"; then
    systemctl start vps-guardian-net-helper.socket >/dev/null 2>&1 || true
  fi
}
completed=false
on_exit() {
  status=$?
  trap - EXIT HUP INT TERM
  if ! "$completed"; then
    rollback
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -o root -g root -m 0700 /var/lib/vps-guardian-net-helper
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$binary" /usr/local/libexec/vps-guardian-net-helper
install -o root -g root -m 0644 \
  "$source_dir/vps-guardian-net-helper.socket" \
  /etc/systemd/system/vps-guardian-net-helper.socket
install -o root -g root -m 0644 \
  "$source_dir/vps-guardian-net-helper@.service" \
  /etc/systemd/system/vps-guardian-net-helper@.service
systemctl daemon-reload
systemctl enable --now vps-guardian-net-helper.socket
systemctl is-active --quiet vps-guardian-net-helper.socket
completed=true
trap - EXIT HUP INT TERM
echo "helper installed; rollback backup: $backup"
