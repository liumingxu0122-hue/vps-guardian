#!/bin/sh
set -eu

secrets_dir=''
refresh='false'
destroy='false'
confirmation=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --secrets-dir) secrets_dir="$2"; shift 2 ;;
    --refresh) refresh='true'; shift ;;
    --destroy-runtime) destroy='true'; shift ;;
    --confirm) confirmation="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "runtime Secret preparation must run as root" >&2
  exit 77
fi
if [ -z "$secrets_dir" ]; then
  echo "usage: $0 --secrets-dir DIRECTORY [--refresh --confirm 'REFRESH COMPOSE SECRETS'] [--destroy-runtime --confirm 'DESTROY RUNTIME SECRETS']" >&2
  exit 64
fi
command -v flock >/dev/null 2>&1 || { echo "flock is required" >&2; exit 69; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 69; }
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
switch_helper="$script_dir/atomic-directory-switch.py"
materializer="$script_dir/materialize-runtime-secret.py"
for helper in "$switch_helper" "$materializer"; do
  [ -f "$helper" ] && [ ! -L "$helper" ] || {
    echo "runtime Secret helper is missing or unsafe" >&2
    exit 69
  }
done
case "$secrets_dir" in
  /*) ;;
  *) echo "Secret directory must be absolute" >&2; exit 64 ;;
esac
[ -d "$secrets_dir" ] && [ ! -L "$secrets_dir" ] && \
  [ "$(readlink -f "$secrets_dir")" = "$secrets_dir" ] && \
  [ "$(stat -c '%u:%g:%a' "$secrets_dir")" = '0:0:700' ] || {
  echo "canonical Secret directory must be root:root with mode 0700" >&2
  exit 77
}
exec 9<>"$secrets_dir/.runtime.lock"
chmod 0600 "$secrets_dir/.runtime.lock"
flock -n 9 || { echo "another runtime Secret transaction is active" >&2; exit 75; }
runtime_dir="$secrets_dir/runtime"

if [ "$destroy" = 'true' ]; then
  [ "$refresh" = 'false' ] && [ "$confirmation" = 'DESTROY RUNTIME SECRETS' ] || {
    echo "runtime Secret destruction requires exact confirmation" >&2
    exit 64
  }
  if [ -e "$runtime_dir" ] || [ -L "$runtime_dir" ]; then
    [ -d "$runtime_dir" ] && [ ! -L "$runtime_dir" ] && \
      [ "$(readlink -f "$runtime_dir")" = "$runtime_dir" ] && \
      [ "$(stat -c '%u:%g:%a' "$runtime_dir")" = '0:0:711' ] || {
      echo "runtime Secret directory is unsafe" >&2
      exit 77
    }
    rm -rf -- "$runtime_dir"
  fi
  for previous in "$secrets_dir"/runtime.previous.*; do
    [ -e "$previous" ] || continue
    case "$(readlink -f "$previous")" in
      "$secrets_dir"/runtime.previous.*) rm -rf -- "$previous" ;;
      *) echo "previous runtime Secret path escaped its root" >&2; exit 77 ;;
    esac
  done
  echo "destroyed runtime Secret copies; canonical Secrets were not modified"
  exit 0
fi

[ -z "$(find "$secrets_dir" -maxdepth 1 -type d -name '.runtime.new.*' -print -quit)" ] || {
  echo "an incomplete runtime Secret transaction requires review" >&2
  exit 73
}
if [ -e "$runtime_dir" ] || [ -L "$runtime_dir" ]; then
  [ "$refresh" = 'true' ] && [ "$confirmation" = 'REFRESH COMPOSE SECRETS' ] || {
    echo "runtime Secret directory exists; exact refresh confirmation is required" >&2
    exit 73
  }
fi

required='postgres-password database-url jwt-secret field-encryption-key enrollment-token proxy-auth controller-ed25519.pem restic-password server.crt server.key'
s3_optional='aws-access-key-id aws-secret-access-key aws-region'
agent_ca_certificate="$secrets_dir/pki/agent-ca.crt"
agent_ca_private_key="$secrets_dir/pki/private/agent-ca.key"
for name in $required; do
  path="$secrets_dir/$name"
  [ -f "$path" ] && [ ! -L "$path" ] && [ -s "$path" ] || {
    echo "required canonical Secret is missing, empty, or unsafe: $name" >&2
    exit 66
  }
  [ "$(stat -c '%u:%g:%a' "$path")" = '0:0:600' ] || {
    echo "canonical Secret must be root:root with mode 0600: $name" >&2
    exit 77
  }
done
for path in "$agent_ca_certificate" "$agent_ca_private_key"; do
  [ -f "$path" ] && [ ! -L "$path" ] && [ -s "$path" ] && \
    [ "$(stat -c '%u:%g:%a' "$path")" = '0:0:600' ] || {
    echo "canonical Agent CA material must be root:root with mode 0600" >&2
    exit 77
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
      path="$secrets_dir/$name"
      [ -f "$path" ] && [ ! -L "$path" ] && [ -s "$path" ] && \
        [ "$(stat -c '%u:%g:%a' "$path")" = '0:0:600' ] || {
        echo "S3 canonical Secret must be root:root with mode 0600: $name" >&2
        exit 77
      }
    done
    ;;
  *) echo "S3 Secrets must be supplied as one complete set" >&2; exit 66 ;;
esac

umask 077
staged="$(mktemp -d "$secrets_dir/.runtime.new.XXXXXX")"
chown root:root "$staged"
chmod 0711 "$staged"
previous=''
cleanup_staged() {
  [ -n "$staged" ] || return 0
  rm -rf -- "$staged"
}
trap cleanup_staged EXIT
trap 'exit 75' HUP INT TERM

install -d -o 70 -g 70 -m 0500 "$staged/postgresql"
install -d -o 10001 -g 10001 -m 0500 "$staged/controller"
install -d -o 99 -g 99 -m 0500 "$staged/gateway"
install -d -o 10002 -g 10002 -m 0500 "$staged/backup"

materialize() {
  service="$1"
  uid="$2"
  gid="$3"
  source="$4"
  name="$5"
  maximum="$6"
  python3 "$materializer" \
    --canonical-root "$secrets_dir" \
    --runtime-root "$staged" \
    --source "$source" \
    --target "$staged/$service/$name" \
    --uid "$uid" --gid "$gid" --maximum-bytes "$maximum"
}

materialize postgresql 70 70 "$secrets_dir/postgres-password" postgres-password 4096
for name in database-url jwt-secret field-encryption-key enrollment-token proxy-auth controller-ed25519.pem; do
  materialize controller 10001 10001 "$secrets_dir/$name" "$name" 4096
done
materialize controller 10001 10001 "$agent_ca_certificate" agent-ca.crt 32768
materialize controller 10001 10001 "$agent_ca_private_key" agent-ca.key 32768
materialize gateway 99 99 "$secrets_dir/proxy-auth" proxy-auth 4096
materialize gateway 99 99 "$secrets_dir/server.crt" server.crt 32768
materialize gateway 99 99 "$secrets_dir/server.key" server.key 32768
materialize backup 10002 10002 "$secrets_dir/database-url" database-url 4096
materialize backup 10002 10002 "$secrets_dir/restic-password" restic-password 4096
if [ "$s3_count" -eq 3 ]; then
  for name in $s3_optional; do
    materialize backup 10002 10002 "$secrets_dir/$name" "$name" 512
  done
fi

if [ -e "$runtime_dir" ]; then
  previous="$secrets_dir/runtime.previous.$(date -u +%Y%m%dT%H%M%SZ).$$"
  [ ! -e "$previous" ] || {
    echo "previous runtime Secret directory already exists" >&2
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
printf 'prepared isolated non-root runtime Secret mounts under %s\n' "$runtime_dir"
