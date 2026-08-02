#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
validator="$repo_root/operations/scripts/validate_compose_secret_files.py"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

base="$work/base"
overlay="$work/overlay"
project="$work/project"
approved="$project/runtime/secrets"
install -d -m 0700 "$base" "$overlay" "$approved"
install -m 0600 /dev/null "$approved/relative"
install -m 0600 /dev/null "$approved/absolute"

cat >"$base/compose.yml" <<'YAML'
services:
  check:
    image: busybox:1.36
    command: ["true"]
    secrets: [relative]
secrets:
  relative:
    file: ./runtime/secrets/relative
YAML

cat >"$overlay/overlay.yml" <<YAML
services:
  check:
    secrets: [absolute]
secrets:
  absolute:
    file: $approved/absolute
YAML

python3 "$validator" \
  --approved-root "$approved" \
  --relative-to "$project" \
  --compose-command docker compose \
    --project-directory "$project" \
    -f "$base/compose.yml" \
    -f "$overlay/overlay.yml" \
    config --format json >/dev/null

install -d -m 0700 "$approved/runtime/runtime"
install -m 0600 /dev/null "$approved/runtime/runtime/duplicate"
printf '{"secrets":{"bad":{"file":"%s"}}}\n' \
  "$approved/runtime/runtime/duplicate" >"$work/duplicate.json"
if python3 "$validator" --approved-root "$approved" --config-file "$work/duplicate.json"; then
  echo "duplicate runtime path was accepted" >&2
  exit 1
fi

install -m 0600 /dev/null "$work/escape"
printf '{"secrets":{"bad":{"file":"%s"}}}\n' "$work/escape" >"$work/escape.json"
if python3 "$validator" --approved-root "$approved" --config-file "$work/escape.json"; then
  echo "path escape was accepted" >&2
  exit 1
fi
