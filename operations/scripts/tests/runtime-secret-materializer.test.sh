#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
canonical="$work/canonical"
install -d -o root -g root -m 0700 "$canonical" "$canonical/pki" "$canonical/pki/private"
required=(postgres-password database-url jwt-secret field-encryption-key enrollment-token
  proxy-auth controller-ed25519.pem restic-password server.crt server.key)
for name in "${required[@]}"; do
  printf 'test-only-%s\n' "$name" >"$canonical/$name"
  chmod 0600 "$canonical/$name"
done
printf 'test-only-agent-ca-certificate\n' >"$canonical/pki/agent-ca.crt"
printf 'test-only-agent-ca-private-key\n' >"$canonical/pki/private/agent-ca.key"
chmod 0600 "$canonical/pki/agent-ca.crt" "$canonical/pki/private/agent-ca.key"

sh "$repo_root/scripts/prepare-compose-secrets.sh" --secrets-dir "$canonical" >/dev/null
runtime="$canonical/runtime"
test "$(stat -c '%u:%g:%a' "$runtime")" = 0:0:711
contracts=(
  'postgresql/postgres-password:70:70'
  'controller/database-url:10001:10001'
  'controller/agent-ca.key:10001:10001'
  'gateway/proxy-auth:99:99'
  'gateway/server.key:99:99'
  'backup/database-url:10002:10002'
  'backup/restic-password:10002:10002'
)
for contract in "${contracts[@]}"; do
  path=${contract%%:*}
  remainder=${contract#*:}
  uid=${remainder%%:*}
  gid=${remainder##*:}
  test "$(stat -c '%u:%g:%a' "$runtime/$path")" = "$uid:$gid:400"
done

old_inode=$(stat -c '%i' "$runtime/controller/database-url")
sh "$repo_root/scripts/prepare-compose-secrets.sh" --secrets-dir "$canonical" \
  --refresh --confirm 'REFRESH COMPOSE SECRETS' >/dev/null
new_inode=$(stat -c '%i' "$runtime/controller/database-url")
test "$old_inode" != "$new_inode"
test -z "$(find "$canonical" -type f -name '.*.new.*' -print -quit)"

chmod 0640 "$canonical/jwt-secret"
if sh "$repo_root/scripts/prepare-compose-secrets.sh" --secrets-dir "$canonical" \
  --refresh --confirm 'REFRESH COMPOSE SECRETS' >/dev/null 2>&1; then
  echo "unsafe canonical mode was accepted" >&2
  exit 1
fi
chmod 0600 "$canonical/jwt-secret"
test "$(stat -c '%u:%g:%a' "$runtime/controller/jwt-secret")" = 10001:10001:400

sh "$repo_root/scripts/prepare-compose-secrets.sh" --secrets-dir "$canonical" \
  --destroy-runtime --confirm 'DESTROY RUNTIME SECRETS' >/dev/null
test ! -e "$runtime"
for name in "${required[@]}"; do test -f "$canonical/$name"; done
