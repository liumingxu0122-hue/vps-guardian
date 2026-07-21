#!/bin/sh
set -eu

release=''
approval_id=''
confirmation=''
execute='false'
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) release="$2"; shift 2 ;;
    --approval-id) approval_id="$2"; shift 2 ;;
    --confirm) confirmation="$2"; shift 2 ;;
    --execute) execute='true'; shift ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then echo "rollback must run as root" >&2; exit 77; fi
core_systemd_units='vps-guardian-controller.service vps-guardian-backup.service vps-guardian-backup.timer'
freshness_systemd_units='vps-guardian-backup-freshness.service vps-guardian-backup-freshness.timer'
managed_systemd_units="$core_systemd_units $freshness_systemd_units"
if [ "$execute" != 'true' ] || [ -z "$approval_id" ] || [ "$confirmation" != 'ROLLBACK VPS GUARDIAN' ]; then
  echo "rollback requires --execute, --approval-id, and --confirm 'ROLLBACK VPS GUARDIAN'" >&2
  exit 64
fi
for command in curl dirname find flock getent grep install mktemp python3 readlink rm stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing command: $command" >&2
    exit 69
  }
done
lifecycle_lock_dir='/run/vps-guardian'
if [ -e "$lifecycle_lock_dir" ] || [ -L "$lifecycle_lock_dir" ]; then
  [ -d "$lifecycle_lock_dir" ] && [ ! -L "$lifecycle_lock_dir" ] && \
    [ "$(readlink -f -- "$lifecycle_lock_dir")" = "$lifecycle_lock_dir" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$lifecycle_lock_dir")" = 'root:root:755' ] || {
    echo "$lifecycle_lock_dir must be root-owned with mode 0755" >&2
    exit 77
  }
else
  install -d -o root -g root -m 0755 "$lifecycle_lock_dir"
fi
lifecycle_lock="$lifecycle_lock_dir/controller-lifecycle.lock"
if [ ! -e "$lifecycle_lock" ] && [ ! -L "$lifecycle_lock" ]; then
  (umask 077; set -C; : > "$lifecycle_lock") 2>/dev/null || true
fi
[ -f "$lifecycle_lock" ] && [ ! -L "$lifecycle_lock" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$lifecycle_lock")" = 'root:root:600' ] || {
  echo "$lifecycle_lock must be a root-owned regular file with mode 0600" >&2
  exit 77
}
exec 9<>"$lifecycle_lock"
flock -n 9 || { echo "another controller lifecycle operation is active" >&2; exit 75; }
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)" || {
  echo "rollback script directory cannot be resolved" >&2
  exit 66
}
journal_tool="$script_dir/lifecycle-journal.py"
[ -f "$journal_tool" ] && [ ! -L "$journal_tool" ] && \
  [ "$(readlink -f -- "$journal_tool")" = "$journal_tool" ] || {
  echo "rollback script has no trusted lifecycle journal helper" >&2
  exit 66
}
journal_root='/var/lib/vps-guardian-lifecycle'
journal_file="$journal_root/controller.json"
lifecycle_journal() {
  python3 "$journal_tool" --root "$journal_root" --journal "$journal_file" "$@"
}
recovery_helper="$script_dir/recover-controller-lifecycle.sh"
[ -f "$recovery_helper" ] && [ ! -L "$recovery_helper" ] && \
  [ "$(readlink -f -- "$recovery_helper")" = "$recovery_helper" ] || {
  echo "rollback script has no trusted controller recovery helper" >&2
  exit 66
}
run_lifecycle_recovery() {
  sh "$recovery_helper" --expected-operation rollback --lock-fd 9
}
if [ -e "$journal_file" ] || [ -L "$journal_file" ]; then
  exec sh "$recovery_helper" --expected-operation rollback --lock-fd 9
fi

install_root='/opt/vps-guardian'
releases_root="$install_root/releases"
current_link="$install_root/current"
[ -d /opt ] && [ ! -L /opt ] && [ "$(readlink -f -- /opt)" = '/opt' ] && \
  [ "$(stat -c '%U:%G:%a' -- /opt)" = 'root:root:755' ] && \
  [ -d "$install_root" ] && [ ! -L "$install_root" ] && \
  [ "$(readlink -f -- "$install_root")" = "$install_root" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$install_root")" = 'root:root:755' ] && \
  [ -d "$releases_root" ] && [ ! -L "$releases_root" ] && \
  [ "$(readlink -f -- "$releases_root")" = "$releases_root" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$releases_root")" = 'root:root:755' ] && \
  [ -L "$current_link" ] && \
  [ "$(stat -c '%U:%G' -- "$current_link")" = 'root:root' ] || {
  echo "controller installation paths are not root-controlled" >&2
  exit 77
}
current_raw="$(readlink -- "$current_link")" || {
  echo "current release link cannot be resolved" >&2
  exit 65
}
case "$current_raw" in
  "$releases_root"/*) current_release_id="${current_raw#"$releases_root"/}" ;;
  *) echo "current release must be a direct child of $releases_root" >&2; exit 65 ;;
esac
case "$current_release_id" in
  ''|*/*|.|..) echo "current release must be a direct child of $releases_root" >&2; exit 65 ;;
esac
[ -d "$current_raw" ] && [ ! -L "$current_raw" ] || {
  echo "current release must be a regular directory" >&2
  exit 65
}

# Reject an untrusted rollback path before reading any current-release metadata.
# This keeps traversal, nested paths, aliases and dangling targets from being
# laundered into a later manifest or unit-snapshot error.
case "$release" in
  "$releases_root"/*) release_id="${release#"$releases_root"/}" ;;
  *) echo "release must be a direct child of $releases_root" >&2; exit 65 ;;
esac
case "$release_id" in
  ''|*/*|.|..) echo "release must be a direct child of $releases_root" >&2; exit 65 ;;
esac
[ -d "$release" ] && [ ! -L "$release" ] || {
  echo "rollback release must be a regular directory" >&2
  exit 65
}
resolved="$(readlink -f -- "$release")" || {
  echo "rollback release cannot be resolved" >&2
  exit 65
}
[ "$resolved" = "$release" ] || {
  echo "rollback release cannot contain symbolic-link path components" >&2
  exit 65
}

current="$(readlink -f -- "$current_raw")" || {
  echo "current release cannot be resolved" >&2
  exit 65
}
manifest_tool="$current/scripts/release-manifest.py"
[ -f "$manifest_tool" ] && [ ! -L "$manifest_tool" ] && \
  [ "$(readlink -f -- "$manifest_tool")" = "$manifest_tool" ] || {
  echo "current release has no trusted exact manifest verifier" >&2
  exit 66
}
[ "$current" = "$current_raw" ] || {
  echo "current release cannot contain symbolic-link path components" >&2
  exit 65
}

if [ ! -x "$resolved/.venv/bin/uvicorn" ]; then echo "target release is incomplete" >&2; exit 66; fi
unit_store_root='/var/lib/vps-guardian-units'
unit_store="$unit_store_root/$release_id"
[ -d "$unit_store_root" ] && [ ! -L "$unit_store_root" ] && \
  [ "$(readlink -f -- "$unit_store_root")" = "$unit_store_root" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$unit_store_root")" = 'root:root:755' ] && \
  [ -d "$unit_store" ] && [ ! -L "$unit_store" ] && \
  [ "$(readlink -f -- "$unit_store")" = "$unit_store" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$unit_store")" = 'root:root:700' ] || {
  echo "target release has no root-controlled systemd unit snapshot" >&2
  exit 66
}
target_systemd_units="$core_systemd_units"
target_has_freshness='false'
target_freshness_service='false'
target_freshness_timer='false'
if [ -e "$unit_store/vps-guardian-backup-freshness.service" ] || \
   [ -L "$unit_store/vps-guardian-backup-freshness.service" ]; then
  target_freshness_service='true'
fi
if [ -e "$unit_store/vps-guardian-backup-freshness.timer" ] || \
   [ -L "$unit_store/vps-guardian-backup-freshness.timer" ]; then
  target_freshness_timer='true'
fi
[ "$target_freshness_service" = "$target_freshness_timer" ] || {
  echo 'target release freshness unit snapshot is incomplete' >&2
  exit 77
}
if [ "$target_freshness_service" = 'true' ]; then
  target_systemd_units="$managed_systemd_units"
  target_has_freshness='true'
fi
for unit in $target_systemd_units; do
  [ -f "$unit_store/$unit" ] && [ ! -L "$unit_store/$unit" ] && \
    [ "$(readlink -f -- "$unit_store/$unit")" = "$unit_store/$unit" ] && \
    [ "$(stat -c '%U:%G:%a' "$unit_store/$unit")" = 'root:root:644' ] || {
    echo "target release systemd snapshot is missing or unsafe: $unit" >&2
    exit 77
  }
done
committed_marker="$unit_store/COMMITTED"
[ -f "$committed_marker" ] && [ ! -L "$committed_marker" ] && \
  [ "$(readlink -f -- "$committed_marker")" = "$committed_marker" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$committed_marker")" = 'root:root:400' ] || {
  echo "target release has no trusted COMMITTED marker" >&2
  exit 66
}
committed_value=''
IFS= read -r committed_value < "$committed_marker" || true
[ "$committed_value" = "$resolved" ] || {
  echo "target release COMMITTED marker does not match the requested release" >&2
  exit 66
}
[ "$(stat -c '%U:%G:%a' -- "$resolved")" = 'root:guardian-release:550' ] && \
  [ -z "$(find "$resolved" \( -type f -o -type d \) \
    \( ! -uid 0 -o -perm /022 \) -print -quit)" ] && \
  [ -z "$(find "$resolved" -type l -print -quit)" ] || {
  echo "target release is not an immutable root-owned tree" >&2
  exit 66
}
release_manifest="$unit_store/RELEASE.MANIFEST.json"
[ -f "$release_manifest" ] && [ ! -L "$release_manifest" ] && \
  [ "$(readlink -f -- "$release_manifest")" = "$release_manifest" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$release_manifest")" = 'root:root:400' ] && \
  python3 "$manifest_tool" verify "$resolved" "$release_manifest" || {
  echo "target release checksum manifest is missing or invalid" >&2
  exit 66
}
grep -Fqx \
  'Environment=GUARDIAN_DATABASE_URL_FILE=/etc/vps-guardian/database-url' \
  "$unit_store/vps-guardian-controller.service" && \
  grep -Fqx \
    'Environment=GUARDIAN_CONTROLLER_SIGNING_KEY_FILE=/etc/vps-guardian/controller-ed25519.pem' \
    "$unit_store/vps-guardian-controller.service" && \
  grep -Fqx \
    'SupplementaryGroups=guardian-release guardian-database' \
    "$unit_store/vps-guardian-controller.service" || {
  echo "target controller unit does not use the fixed database/key trust boundaries" >&2
  exit 66
}
controller_env='/etc/vps-guardian/controller.env'
database_url_file='/etc/vps-guardian/database-url'
controller_signing_key='/etc/vps-guardian/controller-ed25519.pem'
[ -d /etc/vps-guardian ] && [ ! -L /etc/vps-guardian ] && \
  [ "$(readlink -f -- /etc/vps-guardian)" = '/etc/vps-guardian' ] && \
  [ "$(stat -c '%U:%G:%a' -- /etc/vps-guardian)" = \
    'root:guardian-database:750' ] && \
  [ -f "$controller_env" ] && [ ! -L "$controller_env" ] && \
  [ "$(readlink -f -- "$controller_env")" = "$controller_env" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$controller_env")" = 'root:root:600' ] && \
  [ -f "$database_url_file" ] && [ ! -L "$database_url_file" ] && \
  [ "$(readlink -f -- "$database_url_file")" = "$database_url_file" ] && \
  [ -s "$database_url_file" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$database_url_file")" = \
    'root:guardian-database:640' ] && \
  [ -f "$controller_signing_key" ] && [ ! -L "$controller_signing_key" ] && \
  [ "$(readlink -f -- "$controller_signing_key")" = "$controller_signing_key" ] && \
  [ -s "$controller_signing_key" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$controller_signing_key")" = 'root:guardian:640' ] || {
  echo "Controller Secret directory, environment, database URL, or signing key is unsafe" >&2
  exit 77
}
if grep -Eq \
  '^[[:space:]]*(export[[:space:]]+)?GUARDIAN_CONTROLLER_SIGNING_KEY_FILE[[:space:]]*=' \
  "$controller_env"; then
  echo "$controller_env cannot override the fixed Controller signing-key path" >&2
  exit 77
fi
if grep -Eq \
  '^[[:space:]]*(export[[:space:]]+)?GUARDIAN_DATABASE_URL[[:space:]]*=' \
  "$controller_env"; then
  echo "$controller_env cannot define GUARDIAN_DATABASE_URL; use /etc/vps-guardian/database-url" >&2
  exit 77
fi
getent group guardian-release >/dev/null 2>&1 && \
  getent group guardian-database >/dev/null 2>&1 || {
    echo "guardian release/database groups are missing" >&2
    exit 77
  }
for service_user in guardian guardian-backup; do
  id "$service_user" >/dev/null 2>&1 || {
    echo "$service_user service identity is missing" >&2
    exit 77
  }
  for service_group in guardian-release guardian-database; do
    id -nG "$service_user" | tr ' ' '\n' | grep -Fx "$service_group" >/dev/null || {
      echo "$service_user lacks $service_group access" >&2
      exit 77
    }
  done
done
if id -nG guardian-backup | tr ' ' '\n' | grep -Fx guardian >/dev/null; then
  echo "guardian-backup must not belong to the guardian private-key group" >&2
  exit 77
fi
grep -Fqx 'User=guardian-backup' "$unit_store/vps-guardian-backup.service" && \
  grep -Fqx 'Group=guardian-backup' "$unit_store/vps-guardian-backup.service" && \
  grep -Fqx \
    'SupplementaryGroups=guardian-release guardian-database' \
    "$unit_store/vps-guardian-backup.service" && \
  grep -Fqx \
    'Environment=GUARDIAN_DATABASE_URL_FILE=/etc/vps-guardian/database-url' \
    "$unit_store/vps-guardian-backup.service" && \
  grep -Fqx \
    'InaccessiblePaths=/etc/vps-guardian/controller.env /etc/vps-guardian/controller-ed25519.pem' \
    "$unit_store/vps-guardian-backup.service" || {
  echo "target backup unit does not use the isolated backup trust boundaries" >&2
  exit 77
}
backup_secrets='/etc/vps-guardian-backup-secrets'
[ -d "$backup_secrets" ] && [ ! -L "$backup_secrets" ] && \
  [ "$(readlink -f -- "$backup_secrets")" = "$backup_secrets" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$backup_secrets")" = 'root:guardian-backup:750' ] || {
  echo "$backup_secrets is missing or unsafe" >&2
  exit 77
}
[ ! -e "$backup_secrets/database-url" ] && [ ! -L "$backup_secrets/database-url" ] || {
  echo "$backup_secrets/database-url is an obsolete duplicate database URL" >&2
  exit 77
}
unset GUARDIAN_DATABASE_URL
set -a
. "$controller_env"
set +a
export GUARDIAN_DATABASE_URL_FILE="$database_url_file"
export GUARDIAN_CONTROLLER_SIGNING_KEY_FILE="$controller_signing_key"
rollback_id="$(date -u +%Y%m%dT%H%M%SZ)"
unit_backup_dir="/var/backups/vps-guardian-controller/rollback-$rollback_id/systemd"
switch_current() {
  switch_target="$1"
  switch_dir="$(mktemp -d "$install_root/.current-switch.XXXXXX")" || return 1
  if ! chmod 0700 -- "$switch_dir"; then
    rmdir -- "$switch_dir" || true
    return 1
  fi
  if ! ln -s "$switch_target" "$switch_dir/current"; then
    rmdir -- "$switch_dir" || true
    return 1
  fi
  if ! mv -Tf "$switch_dir/current" "$current_link"; then
    rm -f -- "$switch_dir/current"
    rmdir -- "$switch_dir" || true
    return 1
  fi
  rmdir -- "$switch_dir" || true
}
verify_release_database() {
  verified_release="$1"
  su -s /bin/sh guardian -c \
    "cd '$verified_release' && '$verified_release/.venv/bin/alembic' -c controller/alembic.ini current --check-heads" && \
  su -s /bin/sh guardian -c \
    "cd '$verified_release' && '$verified_release/.venv/bin/python' -c 'from sqlalchemy import select; from guardian.database import SessionLocal; from guardian.models import Agent, Approval, AuditLog, Host, Incident, RecoveryPoint; db = SessionLocal(); [db.execute(select(model.id).limit(1)).all() for model in (Host, Agent, Incident, Approval, AuditLog, RecoveryPoint)]; db.close()'"
}
verify_release_offline() {
  verified_release="$1"
  verify_release_database "$verified_release" && \
  su -s /bin/sh guardian -c \
    "cd '$verified_release' && '$verified_release/.venv/bin/python' -c 'from guardian.api import readiness; from guardian.database import SessionLocal; from guardian.main import app; assert any(route.path == \"/ready\" for route in app.routes); db = SessionLocal(); readiness(db); db.close()'"
}
verify_running_release() {
  verified_release="$1"
  curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    http://127.0.0.1:8090/health >/dev/null && \
  curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    http://127.0.0.1:8090/ready >/dev/null && \
  verify_release_offline "$verified_release"
}
restore_previous_application() {
  run_lifecycle_recovery
}
[ ! -e "${unit_backup_dir%/systemd}" ] && [ ! -L "${unit_backup_dir%/systemd}" ] || {
  echo "rollback transaction path already exists: ${unit_backup_dir%/systemd}" >&2
  exit 73
}
install -d -o root -g root -m 0700 "$unit_backup_dir"
current_systemd_units="$core_systemd_units"
current_has_freshness='false'
current_freshness_service='false'
current_freshness_timer='false'
if [ -e /etc/systemd/system/vps-guardian-backup-freshness.service ] || \
   [ -L /etc/systemd/system/vps-guardian-backup-freshness.service ]; then
  current_freshness_service='true'
fi
if [ -e /etc/systemd/system/vps-guardian-backup-freshness.timer ] || \
   [ -L /etc/systemd/system/vps-guardian-backup-freshness.timer ]; then
  current_freshness_timer='true'
fi
[ "$current_freshness_service" = "$current_freshness_timer" ] || {
  echo 'installed systemd freshness unit set is incomplete' >&2
  exit 66
}
if [ "$current_freshness_service" = 'true' ]; then
  current_systemd_units="$managed_systemd_units"
  current_has_freshness='true'
fi
for unit in $current_systemd_units; do
  unit_path="/etc/systemd/system/$unit"
  [ -f "$unit_path" ] && [ ! -L "$unit_path" ] && \
    [ "$(readlink -f -- "$unit_path")" = "$unit_path" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$unit_path")" = 'root:root:644' ] || {
    echo "installed systemd unit is missing or unsafe: $unit" >&2
    exit 66
  }
  cp -p "$unit_path" "$unit_backup_dir/$unit"
done
timer_was_active='false'
restart_backup_timer() {
  exit_status=$?
  trap - EXIT
  if [ -e "$journal_file" ] || [ -L "$journal_file" ]; then
    if ! run_lifecycle_recovery; then
      echo "previous controller could not be restored during rollback cleanup" >&2
      exit_status=72
    fi
  fi
  exit "$exit_status"
}
trap restart_backup_timer EXIT
trap 'exit 75' HUP INT TERM
if systemctl is-active --quiet vps-guardian-backup.timer; then
  timer_initial_state='active'
  timer_was_active='true'
elif systemctl is-failed --quiet vps-guardian-backup.timer; then
  timer_initial_state='failed'
else
  timer_initial_state='inactive'
fi
if [ "$current_has_freshness" = 'true' ]; then
  if systemctl is-active --quiet vps-guardian-backup-freshness.timer; then
    freshness_timer_initial_state='active'
  elif systemctl is-failed --quiet vps-guardian-backup-freshness.timer; then
    freshness_timer_initial_state='failed'
  else
    freshness_timer_initial_state='inactive'
  fi
  [ "$freshness_timer_initial_state" = "$timer_initial_state" ] || {
    echo 'backup and freshness timers must have the same lifecycle state' >&2
    exit 72
  }
fi
for service in vps-guardian-backup.service vps-guardian-backup-freshness.service; do
  if systemctl is-active --quiet "$service"; then
    echo "a backup scheduling operation is already running; retry after it completes" >&2
    exit 75
  fi
done
systemctl is-active --quiet vps-guardian-controller.service || {
  echo "current controller must be active before the rollback outage" >&2
  exit 72
}
if [ "$current_has_freshness" = 'true' ]; then
  lifecycle_journal init --operation rollback --previous-release "$current" \
    --candidate-release "$resolved" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-controller.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup.timer" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup-freshness.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup-freshness.timer" \
    --timer-state "$timer_initial_state" --controller-state active >/dev/null
else
  lifecycle_journal init --operation rollback --previous-release "$current" \
    --candidate-release "$resolved" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-controller.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup.timer" \
    --timer-state "$timer_initial_state" --controller-state active >/dev/null
fi
if [ "$timer_initial_state" = 'active' ]; then
  systemctl stop vps-guardian-backup.timer
  if [ "$current_has_freshness" = 'true' ]; then
    systemctl stop vps-guardian-backup-freshness.timer
  fi
fi
lifecycle_journal update --phase prepared >/dev/null
if ! systemctl stop vps-guardian-controller.service; then
  restore_previous_application || true
  echo "current controller could not be quiesced for rollback" >&2
  exit 72
fi
lifecycle_journal update --phase quiesced --controller-state inactive >/dev/null
# The target executes its Alembic and /ready contracts while the current
# Controller is quiesced and before the target can bind the production port.
if ! verify_release_offline "$resolved"; then
  if restore_previous_application; then
    echo "rollback target is not compatible with the current database schema" >&2
    exit 66
  fi
  echo "rollback target compatibility failed and the previous release could not be restored" >&2
  exit 72
fi
for unit in $target_systemd_units; do
  if ! install -o root -g root -m 0644 "$unit_store/$unit" "/etc/systemd/system/$unit"; then
    if restore_previous_application; then
      echo "rollback unit deployment failed; previous release and units restored" >&2
      exit 71
    fi
    echo "rollback unit deployment and previous-release restoration failed" >&2
    exit 72
  fi
done
if [ "$target_has_freshness" != 'true' ]; then
  if [ "$current_has_freshness" = 'true' ]; then
    if ! systemctl disable vps-guardian-backup-freshness.timer; then
      restore_previous_application || true
      echo 'rollback obsolete freshness timer could not be disabled' >&2
      exit 72
    fi
  fi
  for unit in $freshness_systemd_units; do
    if ! rm -f -- "/etc/systemd/system/$unit"; then
      restore_previous_application || true
      echo "rollback obsolete freshness unit removal failed: $unit" >&2
      exit 72
    fi
  done
fi
if ! systemctl daemon-reload; then
  if restore_previous_application; then
    echo "rollback unit reload failed; previous release and units restored" >&2
    exit 71
  fi
  echo "rollback unit reload and previous-release restoration failed" >&2
  exit 72
fi
lifecycle_journal update --phase units_updated >/dev/null
if ! switch_current "$resolved"; then
  if restore_previous_application; then
    echo "rollback target activation failed; previous release and units restored" >&2
    exit 70
  fi
  echo "rollback target activation and previous-release restoration both failed" >&2
  exit 72
fi
lifecycle_journal update --phase candidate_activated >/dev/null
if ! systemctl restart vps-guardian-controller.service || \
   ! verify_running_release "$resolved"; then
  if restore_previous_application; then
    echo "rollback target failed readiness; previous release and units restored" >&2
    exit 70
  fi
  echo "rollback target and previous release both failed readiness" >&2
  exit 72
fi
lifecycle_journal update --phase verified --controller-state active >/dev/null
target_backup_timers='vps-guardian-backup.timer'
if [ "$target_has_freshness" = 'true' ]; then
  target_backup_timers="$target_backup_timers vps-guardian-backup-freshness.timer"
fi
if [ "$timer_was_active" = 'true' ] && \
   { ! systemctl enable --now $target_backup_timers || \
     ! systemctl is-active --quiet vps-guardian-backup.timer || \
     { [ "$target_has_freshness" = 'true' ] && \
       ! systemctl is-active --quiet vps-guardian-backup-freshness.timer; }; }; then
  if restore_previous_application; then
    echo "rollback timer failed; previous release and units restored" >&2
    exit 71
  fi
  echo "rollback timer and previous-release restoration failed" >&2
  exit 72
fi
timer_was_active='false'
lifecycle_journal update --phase committed --controller-state active \
  --timer-state "$timer_initial_state" >/dev/null
lifecycle_journal clear
printf 'rolled back to %s under approval %s\n' "$resolved" "$approval_id"
