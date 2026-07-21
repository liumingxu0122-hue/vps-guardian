#!/bin/sh
set -eu

mode="${1:-backup}"
case "$mode" in
  backup|check-freshness|check-upload-freshness) ;;
  *) echo "usage: $0 backup|check-freshness|check-upload-freshness" >&2; exit 64 ;;
esac
[ "$(id -u)" -eq 0 ] || { echo "Compose backup scheduling must run as root" >&2; exit 77; }

config='/etc/vps-guardian-compose-backup.conf'
[ -f "$config" ] && [ ! -L "$config" ] && \
  [ "$(readlink -f -- "$config")" = "$config" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$config")" = 'root:root:600' ] || {
  echo "$config must be a root-owned regular file with mode 0600" >&2
  exit 77
}

config_value() {
  key="$1"
  count="$(awk -F= -v key="$key" '$1 == key { count += 1 } END { print count + 0 }' "$config")"
  [ "$count" -eq 1 ] || { echo "configuration key must occur exactly once: $key" >&2; exit 78; }
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print }' "$config"
}

compose_root="$(config_value VPS_GUARDIAN_COMPOSE_ROOT)"
compose_env="$(config_value VPS_GUARDIAN_COMPOSE_ENV)"
max_age_seconds="$(config_value VPS_GUARDIAN_BACKUP_MAX_AGE_SECONDS)"
case "$compose_root:$compose_env" in
  /*:/*) ;;
  *) echo "Compose root and environment paths must be absolute" >&2; exit 78 ;;
esac
case "$max_age_seconds" in
  ''|*[!0-9]*) echo "backup maximum age must be an integer" >&2; exit 78 ;;
esac
[ "$max_age_seconds" -ge 3600 ] && [ "$max_age_seconds" -le 604800 ] || {
  echo "backup maximum age must be between one hour and seven days" >&2
  exit 78
}

resolved_root="$(readlink -f -- "$compose_root")" || exit 78
[ "$resolved_root" = "$compose_root" ] && [ -d "$compose_root" ] && [ ! -L "$compose_root" ] && \
  [ "$(stat -c '%U' -- "$compose_root")" = 'root' ] && \
  [ -z "$(find "$compose_root" -maxdepth 0 -perm /022 -print -quit)" ] || {
  echo "Compose root must be a canonical root-owned non-writable directory" >&2
  exit 77
}
for path in "$compose_root/docker-compose.yml" "$compose_root/deploy/restic-s3.compose.yml"; do
  [ -f "$path" ] && [ ! -L "$path" ] && [ "$(readlink -f -- "$path")" = "$path" ] && \
    [ "$(stat -c '%U' -- "$path")" = 'root' ] && \
    [ -z "$(find "$path" -perm /022 -print -quit)" ] || {
    echo "Compose deployment file is missing or unsafe" >&2
    exit 77
  }
done
[ -f "$compose_env" ] && [ ! -L "$compose_env" ] && \
  [ "$(readlink -f -- "$compose_env")" = "$compose_env" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$compose_env")" = 'root:root:600' ] || {
  echo "Compose environment file must be root-owned with mode 0600" >&2
  exit 77
}

state_dir='/var/lib/vps-guardian-compose-backup'
install -d -o root -g root -m 0700 "$state_dir" /run/vps-guardian
exec 9<>/run/vps-guardian/compose-backup.lock
flock -n 9 || { echo "another Compose backup operation is active" >&2; exit 75; }
upload_success_marker="$state_dir/last-upload-success.json"
verified_success_marker="$state_dir/last-verified-recovery.json"

if [ "$mode" != 'backup' ]; then
  if [ "$mode" = 'check-upload-freshness' ]; then
    success_marker="$upload_success_marker"
    expected_kind='upload'
  else
    success_marker="$verified_success_marker"
    expected_kind='verified-recovery'
  fi
  [ -f "$success_marker" ] && [ ! -L "$success_marker" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$success_marker")" = 'root:root:400' ] || {
    echo "no safe Compose $expected_kind freshness marker exists" >&2
    exit 72
  }
  python3 - "$success_marker" "$max_age_seconds" "$expected_kind" <<'PY'
import json
import os
import re
import sys
import time
from datetime import UTC, datetime

path = sys.argv[1]
maximum = int(sys.argv[2])
expected_kind = sys.argv[3]
try:
    with open(path, encoding="utf-8") as handle:
        marker = json.load(handle)
    recorded_at = datetime.fromisoformat(marker["recorded_at"].replace("Z", "+00:00"))
except (OSError, UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(72)
if (
    marker.get("schema") != "vps-guardian-backup-marker/v1"
    or marker.get("kind") != expected_kind
    or re.fullmatch(r"[A-Fa-f0-9]{64}", marker.get("snapshot_id", "")) is None
    or re.fullmatch(r"[A-Fa-f0-9]{64}", marker.get("checksum", "")) is None
    or re.fullmatch(r"(?!0{40})[A-Fa-f0-9]{40}", marker.get("source_commit", "")) is None
    or recorded_at.tzinfo != UTC
):
    raise SystemExit(72)
age = time.time() - recorded_at.timestamp()
mtime_age = time.time() - os.stat(path, follow_symlinks=False).st_mtime
if abs(age - mtime_age) > 5:
    raise SystemExit(72)
if age < 0 or age > maximum:
    raise SystemExit(72)
print(
    f"Compose {expected_kind} freshness PASS: "
    f"age_seconds={int(age)} maximum={maximum} snapshot={marker['snapshot_id'][:12]}"
)
PY
  exit 0
fi

docker_bin="$(command -v docker)" || { echo "Docker is required" >&2; exit 69; }
"$docker_bin" compose --env-file "$compose_env" \
  -f "$compose_root/docker-compose.yml" \
  -f "$compose_root/deploy/restic-s3.compose.yml" config --quiet
"$docker_bin" compose --env-file "$compose_env" \
  -f "$compose_root/docker-compose.yml" \
  -f "$compose_root/deploy/restic-s3.compose.yml" run --rm --no-deps -T \
  recovery-volume-init
backup_result_tmp="$(mktemp "$state_dir/.backup-result.XXXXXX")"
marker_tmp=''
trap 'rm -f "$backup_result_tmp" ${marker_tmp:+"$marker_tmp"}' EXIT
trap 'exit 75' HUP INT TERM
"$docker_bin" compose --env-file "$compose_env" \
  -f "$compose_root/docker-compose.yml" \
  -f "$compose_root/deploy/restic-s3.compose.yml" run --rm --no-deps -T backup \
  guardian-backup controller --host controller --service controller \
  --source /opt/guardian/runbooks > "$backup_result_tmp"
python3 - "$backup_result_tmp" <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        result = json.load(handle)
except (OSError, UnicodeError, json.JSONDecodeError):
    print("Compose backup returned invalid verification metadata", file=sys.stderr)
    raise SystemExit(72)
if (
    not isinstance(result, dict)
    or result.get("uploaded") is not True
    or result.get("repository_checked") is not True
    or result.get("manifest_restored") is not True
    or not isinstance(result.get("verified"), bool)
    or result.get("database_restore_verified") is not result.get("verified")
    or result.get("verification_state")
    != ("verified" if result.get("verified") else "pending")
    or not isinstance(result.get("recorded"), bool)
    or result.get("recording_error")
    not in (None, "inventory_host_not_found", "recovery_point_persistence_failed")
    or (result.get("recorded") is True) != (result.get("recording_error") is None)
    or not isinstance(result.get("snapshot_id"), str)
    or re.fullmatch(r"[A-Fa-f0-9]{64}", result["snapshot_id"]) is None
    or not isinstance(result.get("checksum"), str)
    or re.fullmatch(r"[A-Fa-f0-9]{64}", result["checksum"]) is None
    or not isinstance(result.get("source_commit"), str)
    or re.fullmatch(r"(?!0{40})[A-Fa-f0-9]{40}", result["source_commit"]) is None
):
    print("Compose backup did not produce valid upload metadata", file=sys.stderr)
    raise SystemExit(72)
PY
cat "$backup_result_tmp"

write_success_marker() {
  marker_kind="$1"
  marker_path="$2"
  marker_tmp="$(mktemp "$state_dir/.${marker_kind}-success.XXXXXX")"
  python3 - "$backup_result_tmp" "$marker_kind" > "$marker_tmp" <<'PY'
import json
import sys
from datetime import UTC, datetime

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
marker = {
    "schema": "vps-guardian-backup-marker/v1",
    "kind": sys.argv[2],
    "snapshot_id": result["snapshot_id"],
    "checksum": result["checksum"],
    "source_commit": result["source_commit"],
    "recorded_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
}
json.dump(marker, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
  chown root:root "$marker_tmp"
  chmod 0400 "$marker_tmp"
  python3 - "$marker_tmp" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  mv -Tf "$marker_tmp" "$marker_path"
  marker_tmp=''
  python3 - "$state_dir" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

write_success_marker upload "$upload_success_marker"
if python3 - "$backup_result_tmp" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    raise SystemExit(0 if json.load(handle).get("verified") is True else 1)
PY
then
  write_success_marker verified-recovery "$verified_success_marker"
fi
recording_failed='false'
if ! python3 - "$backup_result_tmp" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    raise SystemExit(0 if json.load(handle).get("recording_error") is None else 1)
PY
then
  recording_failed='true'
fi
rm -f "$backup_result_tmp"
backup_result_tmp=''
trap - EXIT HUP INT TERM
if [ "$recording_failed" = 'true' ]; then
  echo 'Compose backup uploaded successfully but RecoveryPoint recording needs reconciliation' >&2
  exit 72
fi
