#!/bin/sh
set -eu

mode="${1:-backup}"
case "$mode" in
  backup|check-freshness|check-upload-freshness) ;;
  *) echo "usage: $0 backup|check-freshness|check-upload-freshness" >&2; exit 64 ;;
esac
[ "$(id -un)" = 'guardian-backup' ] || {
  echo 'systemd backup scheduling must run as the guardian-backup service account' >&2
  exit 77
}
unset RESTIC_REPOSITORY RESTIC_PASSWORD AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY \
  AWS_SESSION_TOKEN AWS_DEFAULT_REGION GUARDIAN_DATABASE_URL

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
marker_tool="$script_dir/systemd-backup-markers.py"
backup_runner="$script_dir/run-backup-command.sh"
for path in "$marker_tool" "$backup_runner"; do
  [ -f "$path" ] && [ ! -L "$path" ] || {
    echo "systemd backup release helper is missing or unsafe: $path" >&2
    exit 69
  }
done

state_dir='/var/lib/vps-guardian-backup'
upload_marker_name='last-upload-success.json'
verified_marker_name='last-verified-recovery.json'
[ -d "$state_dir" ] && [ ! -L "$state_dir" ] && \
  [ "$(readlink -f -- "$state_dir")" = "$state_dir" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$state_dir")" = 'guardian-backup:guardian-backup:750' ] || {
  echo "$state_dir must belong to guardian-backup with mode 0750" >&2
  exit 77
}

exec 9<"$state_dir"
flock -n 9 || { echo 'another systemd backup marker operation is active' >&2; exit 75; }

if [ "$mode" != 'backup' ]; then
  maximum_age="${GUARDIAN_BACKUP_MAX_AGE_SECONDS:-28800}"
  case "$maximum_age" in
    ''|*[!0-9]*) echo 'backup maximum age must be an integer' >&2; exit 78 ;;
  esac
  if [ "$mode" = 'check-upload-freshness' ]; then
    marker_kind='upload'
    marker_name="$upload_marker_name"
  else
    marker_kind='verified-recovery'
    marker_name="$verified_marker_name"
  fi
  [ -f "$state_dir/$marker_name" ] && [ ! -L "$state_dir/$marker_name" ] || {
    echo "systemd backup freshness marker is missing: $marker_name" >&2
    exit 72
  }
  exec python3 "$marker_tool" check --state-dir "$state_dir" \
    --kind "$marker_kind" --maximum-age "$maximum_age"
fi

backup_result_tmp="$(mktemp "$state_dir/.backup-result.XXXXXX")"
trap 'rm -f "$backup_result_tmp"' EXIT
trap 'exit 75' HUP INT TERM
sh "$backup_runner" guardian-backup controller --host controller --service controller \
  --source /opt/vps-guardian/current/runbooks > "$backup_result_tmp"

set +e
python3 "$marker_tool" record --result "$backup_result_tmp" --state-dir "$state_dir"
marker_status=$?
set -e
case "$marker_status" in
  0)
    cat "$backup_result_tmp"
    rm -f "$backup_result_tmp"
    trap - EXIT HUP INT TERM
    exit 0
    ;;
  3)
    cat "$backup_result_tmp"
    rm -f "$backup_result_tmp"
    trap - EXIT HUP INT TERM
    echo 'systemd backup uploaded successfully but RecoveryPoint recording needs reconciliation' >&2
    exit 72
    ;;
  *)
    rm -f "$backup_result_tmp"
    trap - EXIT HUP INT TERM
    exit "$marker_status"
    ;;
esac
