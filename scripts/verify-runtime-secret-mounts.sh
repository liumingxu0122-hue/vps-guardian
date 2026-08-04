#!/bin/sh
set -eu

runtime_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --runtime-dir) runtime_dir="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "runtime mount verification requires root" >&2; exit 77; }
[ -n "$runtime_dir" ] || { echo "--runtime-dir is required" >&2; exit 64; }
case "$runtime_dir" in /*) ;; *) echo "runtime directory must be absolute" >&2; exit 64 ;; esac
if [ ! -d "$runtime_dir" ] || [ -L "$runtime_dir" ] || \
  [ "$(readlink -f "$runtime_dir")" != "$runtime_dir" ] || \
  [ "$(stat -c '%u:%g:%a' "$runtime_dir")" != '0:0:711' ]; then
  echo "runtime directory is unsafe" >&2
  exit 77
fi
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 69; }

database_image="${VPS_GUARDIAN_DATABASE_IMAGE:-vps-guardian-postgres:0.4.0-alpha.1}"
controller_image="${VPS_GUARDIAN_CONTROLLER_IMAGE:-vps-guardian-controller:0.4.0-alpha.1}"
gateway_image="${VPS_GUARDIAN_GATEWAY_IMAGE:-vps-guardian-agent-gateway:0.4.0-alpha.1}"
contracts="postgresql/postgres-password|70|70|$database_image|primary
controller/database-url|10001|10001|$controller_image|primary
controller/jwt-secret|10001|10001|$controller_image|primary
controller/field-encryption-key|10001|10001|$controller_image|primary
controller/enrollment-token|10001|10001|$controller_image|primary
controller/proxy-auth|10001|10001|$controller_image|primary
controller/controller-ed25519.pem|10001|10001|$controller_image|primary
controller/agent-ca.crt|10001|10001|$controller_image|primary
controller/agent-ca.key|10001|10001|$controller_image|primary
gateway/proxy-auth|99|99|$gateway_image|primary
gateway/server.crt|99|99|$gateway_image|primary
gateway/server.key|99|99|$gateway_image|primary
backup/database-url|10002|10002|$controller_image|backup
backup/restic-password|10002|10002|$controller_image|backup"

printf '%s\n' "$contracts" | while IFS='|' read -r relative uid gid image identity; do
  path="$runtime_dir/$relative"
  if [ ! -f "$path" ] || [ -L "$path" ] || \
    [ "$(readlink -f "$path")" != "$path" ]; then
    echo "runtime Secret is missing or unsafe: $relative" >&2
    exit 77
  fi
  [ "$(stat -c '%u:%g:%a' "$path")" = "$uid:$gid:400" ] || {
    echo "runtime Secret contract mismatch: $relative" >&2
    exit 77
  }
  if [ "$identity" = backup ]; then
    image_contract=$(docker image inspect "$image" \
      --format '{{index .Config.Labels "org.vps-guardian.runtime.backup.uid"}}:{{index .Config.Labels "org.vps-guardian.runtime.backup.gid"}}')
    expected="$uid:$gid"
  else
    image_contract=$(docker image inspect "$image" \
      --format '{{index .Config.Labels "org.vps-guardian.runtime.uid"}}:{{index .Config.Labels "org.vps-guardian.runtime.gid"}}:{{.Config.User}}')
    expected="$uid:$gid:$uid:$gid"
  fi
  [ "$image_contract" = "$expected" ] || {
    echo "image runtime identity contract mismatch: $relative" >&2
    exit 77
  }
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --user "$uid:$gid" --entrypoint sh --mount \
    "type=bind,src=$path,dst=/run/guardian-secret,readonly" "$image" \
    -c 'test -r /run/guardian-secret' >/dev/null
  if docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --user 65534:65534 --entrypoint sh --mount \
    "type=bind,src=$path,dst=/run/guardian-secret,readonly" "$image" \
    -c 'test -r /run/guardian-secret' >/dev/null 2>&1; then
    echo "unrelated UID can read runtime Secret: $relative" >&2
    exit 77
  fi
  printf '%s|uid=%s|gid=%s|mode=0400|target-readable=yes|other-readable=no\n' \
    "$relative" "$uid" "$gid"
done
