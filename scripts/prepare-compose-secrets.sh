#!/bin/sh
set -eu

secrets_dir=''
refresh='false'
confirmation=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --secrets-dir) secrets_dir="$2"; shift 2 ;;
    --refresh) refresh='true'; shift ;;
    --confirm) confirmation="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "runtime Secret preparation must run as root" >&2
  exit 77
fi
if [ -z "$secrets_dir" ]; then
  echo "usage: $0 --secrets-dir DIRECTORY [--refresh --confirm 'REFRESH COMPOSE SECRETS']" >&2
  exit 64
fi
command -v flock >/dev/null 2>&1 || { echo "flock is required" >&2; exit 69; }
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
switch_helper="$script_dir/atomic-directory-switch.py"
[ -f "$switch_helper" ] && [ ! -L "$switch_helper" ] || {
  echo "atomic directory switch helper is missing or unsafe" >&2
  exit 69
}
case "$secrets_dir" in
  /*) ;;
  *) echo "Secret directory must be absolute" >&2; exit 64 ;;
esac
[ -d "$secrets_dir" ] && [ ! -L "$secrets_dir" ] && \
  [ "$(readlink -f "$secrets_dir")" = "$secrets_dir" ] && \
  [ "$(stat -c '%u:%a' "$secrets_dir")" = '0:700' ] || {
  echo "Secret directory must be a root-owned regular directory with mode 0700" >&2
  exit 77
}
exec 9<>"$secrets_dir/.runtime.lock"
flock -n 9 || { echo "another runtime Secret refresh is active" >&2; exit 75; }
[ -z "$(find "$secrets_dir" -maxdepth 1 -type d -name '.runtime.new.*' -print -quit)" ] || {
  echo "an incomplete runtime Secret transaction requires review" >&2
  exit 73
}

required='postgres-password database-url jwt-secret field-encryption-key enrollment-token proxy-auth controller-ed25519.pem restic-password server.crt server.key'
s3_optional='aws-access-key-id aws-secret-access-key aws-region'
agent_ca_certificate="$secrets_dir/pki/agent-ca.crt"
agent_ca_private_key="$secrets_dir/pki/private/agent-ca.key"
for name in $required; do
  [ -f "$secrets_dir/$name" ] && [ ! -L "$secrets_dir/$name" ] && \
    [ -s "$secrets_dir/$name" ] || {
    echo "required master Secret is missing, empty, or unsafe: $name" >&2
    exit 66
  }
  [ "$(stat -c '%u:%a' "$secrets_dir/$name")" = '0:600' ] || {
    echo "required master Secret must be root-owned with mode 0600: $name" >&2
    exit 77
  }
  [ "$(stat -c '%s' "$secrets_dir/$name")" -le 4096 ] || {
    echo "required master Secret is too large: $name" >&2
    exit 66
  }
done

[ -f "$agent_ca_certificate" ] && [ ! -L "$agent_ca_certificate" ] && \
  [ "$(stat -c '%u:%a' "$agent_ca_certificate")" = '0:644' ] || {
  echo "Agent CA certificate must be root-owned with mode 0644" >&2
  exit 77
}
[ -f "$agent_ca_private_key" ] && [ ! -L "$agent_ca_private_key" ] && \
  [ "$(stat -c '%u:%a' "$agent_ca_private_key")" = '0:600' ] || {
  echo "Agent CA private key must be root-owned with mode 0600" >&2
  exit 77
}
for path in "$agent_ca_certificate" "$agent_ca_private_key"; do
  [ -s "$path" ] && [ "$(stat -c '%s' "$path")" -le 32768 ] || {
    echo "Agent CA material is missing, empty, or unexpectedly large" >&2
    exit 66
  }
done

s3_count=0
for name in $s3_optional; do
  if [ -e "$secrets_dir/$name" ] || [ -L "$secrets_dir/$name" ]; then
    s3_count=$((s3_count + 1))
  fi
done
case "$s3_count" in
  0) ;;
  3)
    for name in $s3_optional; do
      [ -f "$secrets_dir/$name" ] && [ ! -L "$secrets_dir/$name" ] && \
        [ -s "$secrets_dir/$name" ] || {
        echo "S3 Secret is missing, empty, or unsafe: $name" >&2
        exit 66
      }
      [ "$(stat -c '%u:%a' "$secrets_dir/$name")" = '0:600' ] || {
        echo "S3 Secret must be root-owned with mode 0600: $name" >&2
        exit 77
      }
      [ "$(stat -c '%s' "$secrets_dir/$name")" -le 512 ] || {
        echo "S3 Secret is too large: $name" >&2
        exit 66
      }
    done
    ;;
  *)
    echo "S3 Secrets must be supplied as a complete access-key, Secret Key, and region set" >&2
    exit 66
    ;;
esac

runtime_dir="$secrets_dir/runtime"
[ ! -L "$runtime_dir" ] || {
  echo "runtime Secret path must not be a symbolic link" >&2
  exit 77
}
if [ -e "$runtime_dir" ]; then
  if [ "$refresh" != 'true' ] || [ "$confirmation" != 'REFRESH COMPOSE SECRETS' ]; then
    echo "runtime Secret directory already exists; explicit refresh confirmation is required" >&2
    exit 73
  fi
fi

umask 077
staged="$(mktemp -d "$secrets_dir/.runtime.new.XXXXXX")"
chown root:root "$staged"
chmod 0700 "$staged"
previous=''
cleanup_staged() {
  [ -n "$staged" ] || return 0
  for name in $required $s3_optional agent-ca.crt agent-ca.key; do
    rm -f "$staged/$name"
  done
  rmdir "$staged" 2>/dev/null || true
}
trap cleanup_staged EXIT
trap 'exit 75' HUP INT TERM
for name in $required; do
  install -o root -g root -m 0444 "$secrets_dir/$name" "$staged/$name"
done
install -o root -g root -m 0444 "$agent_ca_certificate" "$staged/agent-ca.crt"
install -o root -g root -m 0444 "$agent_ca_private_key" "$staged/agent-ca.key"
if [ "$s3_count" -eq 3 ]; then
  for name in $s3_optional; do
    install -o root -g root -m 0444 "$secrets_dir/$name" "$staged/$name"
  done
fi

if [ -e "$runtime_dir" ]; then
  previous="$secrets_dir/runtime.previous.$(date -u +%Y%m%dT%H%M%SZ).$$"
  [ ! -e "$previous" ] || {
    echo "previous runtime Secret directory already exists: $previous" >&2
    exit 73
  }
  refresh_staged="$staged"
  staged=''
  if ! python3 "$switch_helper" refresh "$refresh_staged" "$runtime_dir" "$previous"; then
    echo "runtime Secret refresh failed; the transaction trees were preserved for review" >&2
    exit 74
  fi
else
  python3 "$switch_helper" install "$staged" "$runtime_dir" || exit 74
  staged=''
fi
trap - EXIT HUP INT TERM
printf 'prepared non-root-readable container Secret mounts under %s; recreate controller containers before retiring any runtime.previous.* copy\n' "$runtime_dir"
