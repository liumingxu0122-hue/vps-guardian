#!/bin/sh
set -eu

expected_operation=''
lock_fd=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --expected-operation) expected_operation="$2"; shift 2 ;;
    --lock-fd) lock_fd="$2"; shift 2 ;;
    *) echo "unknown recovery option: $1" >&2; exit 64 ;;
  esac
done
case "$expected_operation" in
  install|upgrade|rollback) ;;
  *) echo 'recovery requires an expected controller lifecycle operation' >&2; exit 64 ;;
esac
case "$lock_fd" in
  ''|*[!0-9]*) echo 'recovery requires a numeric inherited lock descriptor' >&2; exit 64 ;;
esac
[ "$(id -u)" -eq 0 ] || { echo 'controller lifecycle recovery requires root' >&2; exit 77; }
for command in cmp curl dirname find flock grep install mktemp python3 readlink rm stat su systemctl; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing recovery command: $command" >&2
    exit 69
  }
done

lifecycle_lock='/run/vps-guardian/controller-lifecycle.lock'
lock_reference="/proc/self/fd/$lock_fd"
[ -e "$lock_reference" ] && \
  [ "$(readlink -f -- "$lock_reference")" = "$lifecycle_lock" ] && \
  [ "$(stat -Lc '%d:%i' -- "$lock_reference")" = \
    "$(stat -c '%d:%i' -- "$lifecycle_lock")" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$lifecycle_lock")" = 'root:root:600' ] || {
  echo 'controller lifecycle recovery did not inherit the trusted lock descriptor' >&2
  exit 77
}
flock -n "$lock_fd" || {
  echo 'controller lifecycle recovery does not hold the lifecycle lock' >&2
  exit 75
}

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)" || {
  echo 'controller lifecycle recovery script directory cannot be resolved' >&2
  exit 66
}
journal_tool="$script_dir/lifecycle-journal.py"
[ -f "$journal_tool" ] && [ ! -L "$journal_tool" ] && \
  [ "$(readlink -f -- "$journal_tool")" = "$journal_tool" ] || {
  echo 'controller lifecycle recovery has no trusted journal helper' >&2
  exit 66
}
journal_root='/var/lib/vps-guardian-lifecycle'
journal_file="$journal_root/controller.json"
lifecycle_journal() {
  python3 "$journal_tool" --root "$journal_root" --journal "$journal_file" "$@"
}
core_systemd_units='vps-guardian-controller.service vps-guardian-backup.service vps-guardian-backup.timer'
freshness_systemd_units='vps-guardian-backup-freshness.service vps-guardian-backup-freshness.timer'
managed_systemd_units="$core_systemd_units $freshness_systemd_units"

stop_runtime() {
  stop_status=0
  systemctl stop vps-guardian-backup.timer >/dev/null 2>&1 || true
  systemctl stop vps-guardian-backup-freshness.timer >/dev/null 2>&1 || true
  systemctl stop vps-guardian-backup.service >/dev/null 2>&1 || true
  systemctl stop vps-guardian-backup-freshness.service >/dev/null 2>&1 || true
  systemctl stop vps-guardian-controller.service >/dev/null 2>&1 || true
  for unit in vps-guardian-backup.timer vps-guardian-backup-freshness.timer \
    vps-guardian-backup.service vps-guardian-backup-freshness.service \
    vps-guardian-controller.service; do
    if systemctl is-active --quiet "$unit"; then
      stop_status=1
    fi
  done
  return "$stop_status"
}
signal_fail_closed() {
  trap - HUP INT TERM
  stop_runtime || true
  echo 'controller lifecycle recovery interrupted; Controller and backup timers left stopped' >&2
  exit 75
}
trap signal_fail_closed HUP INT TERM

journal_json=''
load_journal() {
  journal_json="$(lifecycle_journal show)"
}
journal_field() {
  printf '%s\n' "$journal_json" | python3 -c \
    'import json,sys; value=json.load(sys.stdin)[sys.argv[1]]; print("" if value is None else value)' \
    "$1"
}
journal_unit_directory() {
  printf '%s\n' "$journal_json" | python3 -c '
import json
import pathlib
import sys

refs = [pathlib.PurePosixPath(value) for value in json.load(sys.stdin)["unit_metadata_refs"]]
names = {
    "vps-guardian-controller.service",
    "vps-guardian-backup.service",
    "vps-guardian-backup.timer",
}
freshness = {
    "vps-guardian-backup-freshness.service",
    "vps-guardian-backup-freshness.timer",
}
parents = {str(ref.parent) for ref in refs}
actual = {ref.name for ref in refs}
if actual not in (names, names | freshness) or len(refs) != len(actual) or len(parents) != 1:
    raise SystemExit(1)
print(parents.pop())
'
}
journal_has_freshness() {
  printf '%s\n' "$journal_json" | python3 -c '
import json
import pathlib
import sys

names = {pathlib.PurePosixPath(value).name for value in json.load(sys.stdin)["unit_metadata_refs"]}
expected = {
    "vps-guardian-backup-freshness.service",
    "vps-guardian-backup-freshness.timer",
}
raise SystemExit(0 if expected <= names else 1)
'
}
direct_release_id() {
  release_path="$1"
  case "$release_path" in
    /opt/vps-guardian/releases/*) release_id="${release_path#/opt/vps-guardian/releases/}" ;;
    *) return 1 ;;
  esac
  case "$release_id" in
    ''|*/*|.|..) return 1 ;;
  esac
  printf '%s\n' "$release_id"
}
validate_snapshot_directory() {
  snapshot_directory="$1"
  snapshot_units="$2"
  [ -d "$snapshot_directory" ] && [ ! -L "$snapshot_directory" ] && \
    [ "$(readlink -f -- "$snapshot_directory")" = "$snapshot_directory" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$snapshot_directory")" = 'root:root:700' ] || return 1
  for unit in $snapshot_units; do
    snapshot="$snapshot_directory/$unit"
    [ -f "$snapshot" ] && [ ! -L "$snapshot" ] && \
      [ "$(readlink -f -- "$snapshot")" = "$snapshot" ] && \
      [ "$(stat -c '%U:%G:%a' -- "$snapshot")" = 'root:root:644' ] || return 1
  done
  case " $snapshot_units " in
    *' vps-guardian-backup-freshness.service '*) ;;
    *)
      for unit in $freshness_systemd_units; do
        [ ! -e "$snapshot_directory/$unit" ] && [ ! -L "$snapshot_directory/$unit" ] || \
          return 1
      done
      ;;
  esac
}
validate_current_target() {
  first_allowed="$1"
  second_allowed="$2"
  current_link='/opt/vps-guardian/current'
  if [ ! -e "$current_link" ] && [ ! -L "$current_link" ]; then
    return 0
  fi
  [ -L "$current_link" ] && [ "$(stat -c '%U:%G' -- "$current_link")" = 'root:root' ] || \
    return 1
  current_value="$(readlink -- "$current_link")" || return 1
  [ "$current_value" = "$first_allowed" ] || [ "$current_value" = "$second_allowed" ]
}
switch_current() {
  switch_target="$1"
  switch_root='/opt/vps-guardian'
  switch_link="$switch_root/current"
  switch_dir="$(mktemp -d "$switch_root/.current-switch.XXXXXX")" || return 1
  if ! chmod 0700 -- "$switch_dir" || \
     ! ln -s "$switch_target" "$switch_dir/current" || \
     ! mv -Tf "$switch_dir/current" "$switch_link"; then
    rm -f -- "$switch_dir/current"
    rmdir -- "$switch_dir" 2>/dev/null || true
    return 1
  fi
  rmdir -- "$switch_dir" 2>/dev/null || true
}
validate_controller_inputs() {
  controller_env='/etc/vps-guardian/controller.env'
  database_url_file='/etc/vps-guardian/database-url'
  signing_key_file='/etc/vps-guardian/controller-ed25519.pem'
  [ -f "$controller_env" ] && [ ! -L "$controller_env" ] && \
    [ "$(readlink -f -- "$controller_env")" = "$controller_env" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$controller_env")" = 'root:root:600' ] && \
    [ -f "$database_url_file" ] && [ ! -L "$database_url_file" ] && \
    [ "$(readlink -f -- "$database_url_file")" = "$database_url_file" ] && \
    [ -s "$database_url_file" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$database_url_file")" = 'root:guardian-database:640' ] && \
    [ -f "$signing_key_file" ] && [ ! -L "$signing_key_file" ] && \
    [ "$(readlink -f -- "$signing_key_file")" = "$signing_key_file" ] && \
    [ -s "$signing_key_file" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$signing_key_file")" = 'root:guardian:640' ] || return 1
  if grep -Eq \
    '^[[:space:]]*(export[[:space:]]+)?GUARDIAN_CONTROLLER_SIGNING_KEY_FILE[[:space:]]*=' \
    "$controller_env"; then
    return 1
  fi
  if grep -Eq \
    '^[[:space:]]*(export[[:space:]]+)?GUARDIAN_DATABASE_URL[[:space:]]*=' \
    "$controller_env"; then
    return 1
  fi
  unset GUARDIAN_DATABASE_URL
  set -a
  . "$controller_env"
  set +a
  export GUARDIAN_DATABASE_URL_FILE="$database_url_file"
  export GUARDIAN_CONTROLLER_SIGNING_KEY_FILE="$signing_key_file"
}
validate_previous_release() {
  previous_release="$1"
  [ -d "$previous_release" ] && [ ! -L "$previous_release" ] && \
    [ "$(readlink -f -- "$previous_release")" = "$previous_release" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$previous_release")" = 'root:guardian-release:550' ] && \
    [ -z "$(find "$previous_release" \( -type f -o -type d \) \
      \( ! -uid 0 -o -perm /022 \) -print -quit)" ] && \
    [ -z "$(find "$previous_release" -type l -print -quit)" ] && \
    [ -x "$previous_release/.venv/bin/alembic" ] && \
    [ -x "$previous_release/.venv/bin/python" ] && \
    [ -x "$previous_release/.venv/bin/uvicorn" ]
}
verify_release_offline() {
  verified_release="$1"
  su -s /bin/sh guardian -c \
    "cd '$verified_release' && '$verified_release/.venv/bin/alembic' -c controller/alembic.ini current --check-heads" && \
  su -s /bin/sh guardian -c \
    "cd '$verified_release' && '$verified_release/.venv/bin/python' -c 'from sqlalchemy import select; from guardian.database import SessionLocal; from guardian.models import Agent, Approval, AuditLog, Host, Incident, RecoveryPoint; db = SessionLocal(); [db.execute(select(model.id).limit(1)).all() for model in (Host, Agent, Incident, Approval, AuditLog, RecoveryPoint)]; db.close()'" && \
  su -s /bin/sh guardian -c \
    "cd '$verified_release' && '$verified_release/.venv/bin/python' -c 'from guardian.api import readiness; from guardian.database import SessionLocal; from guardian.main import app; assert any(route.path == \"/ready\" for route in app.routes); db = SessionLocal(); readiness(db); db.close()'"
}
verify_running_release() {
  verified_release="$1"
  curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    http://127.0.0.1:8090/health >/dev/null && \
  curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    http://127.0.0.1:8090/ready >/dev/null && \
  verify_release_offline "$verified_release" || return 1
  main_pid="$(systemctl show vps-guardian-controller.service --property MainPID --value)" || return 1
  case "$main_pid" in
    ''|0|*[!0-9]*) return 1 ;;
  esac
  [ "$(readlink -f -- "/proc/$main_pid/cwd")" = "$verified_release" ]
}
restore_timer_state() {
  requested_state="$1"
  restore_freshness="$2"
  restore_timers='vps-guardian-backup.timer'
  if [ "$restore_freshness" = 'true' ]; then
    restore_timers="$restore_timers vps-guardian-backup-freshness.timer"
  fi
  case "$requested_state" in
    active)
      systemctl enable --now $restore_timers || return 1
      for timer in $restore_timers; do
        systemctl is-active --quiet "$timer" || return 1
      done
      ;;
    inactive|failed|unknown)
      systemctl stop $restore_timers || return 1
      for timer in $restore_timers; do
        ! systemctl is-active --quiet "$timer" || return 1
      done
      ;;
    *) return 1 ;;
  esac
}

recovery_failure() {
  message="$1"
  stop_runtime || true
  echo "$message; Controller and backup timers stopped, journal retained" >&2
  exit 72
}

if ! load_journal; then
  recovery_failure 'controller lifecycle journal cannot be loaded securely'
fi
operation="$(journal_field operation)"
phase="$(journal_field phase)"
[ "$operation" = "$expected_operation" ] || \
  recovery_failure "journal belongs to $operation, not $expected_operation"
case "$phase" in
  committed)
    trap 'exit 75' HUP INT TERM
    if lifecycle_journal clear; then
      printf 'cleared completed %s lifecycle journal\n' "$operation"
      exit 0
    fi
    echo 'completed lifecycle journal could not be cleared; runtime was not changed' >&2
    exit 72
    ;;
  previous_restored)
    [ "$operation" != 'install' ] || \
      recovery_failure 'install journal has an impossible previous_restored phase'
    trap 'exit 75' HUP INT TERM
    if lifecycle_journal clear; then
      printf 'cleared completed %s recovery journal\n' "$operation"
      exit 0
    fi
    echo 'completed recovery journal could not be cleared; runtime was not changed' >&2
    exit 72
    ;;
  aborted)
    [ "$operation" = 'install' ] || \
      recovery_failure "$operation journal has an impossible aborted phase"
    trap 'exit 75' HUP INT TERM
    if lifecycle_journal clear; then
      echo 'cleared completed install recovery journal'
      exit 0
    fi
    echo 'completed install recovery journal could not be cleared; runtime was not changed' >&2
    exit 72
    ;;
  recovery_started) ;;
  recovery_required) ;;
  initialized|prepared|quiesced|database_updated|units_updated|candidate_activated|verified)
    lifecycle_journal update --phase recovery_required >/dev/null || \
      recovery_failure 'lifecycle journal could not enter recovery'
    load_journal || recovery_failure 'lifecycle journal could not be reloaded'
    phase='recovery_required'
    ;;
  *) recovery_failure "unsupported lifecycle recovery phase $phase" ;;
esac

stop_runtime || recovery_failure 'Guardian runtime could not be quiesced for recovery'
if [ "$phase" = 'recovery_required' ]; then
  lifecycle_journal update --phase recovery_started --controller-state inactive \
    >/dev/null || \
    recovery_failure 'lifecycle recovery start could not be persisted'
  load_journal || recovery_failure 'lifecycle recovery journal could not be reloaded'
fi

candidate_release="$(journal_field candidate_release)"
candidate_id="$(direct_release_id "$candidate_release")" || \
  recovery_failure 'journal candidate is not a direct release child'
timer_state="$(journal_field timer_state)"
snapshot_has_freshness='false'
snapshot_systemd_units="$core_systemd_units"
if journal_has_freshness; then
  snapshot_has_freshness='true'
  snapshot_systemd_units="$managed_systemd_units"
fi

if [ "$operation" = 'install' ]; then
  snapshot_directory="$(journal_unit_directory)" || \
    recovery_failure 'install journal has invalid unit references'
  [ "$snapshot_directory" = "/var/lib/vps-guardian-units/$candidate_id" ] || \
    recovery_failure 'install journal unit references do not match the candidate'
  validate_snapshot_directory "$snapshot_directory" "$snapshot_systemd_units" || \
    recovery_failure 'install candidate unit snapshot is missing or unsafe'
  validate_current_target "$candidate_release" "$candidate_release" || \
    recovery_failure 'install recovery found an unrelated current release'
  for unit in $snapshot_systemd_units; do
    installed="/etc/systemd/system/$unit"
    if [ -e "$installed" ] || [ -L "$installed" ]; then
      [ -f "$installed" ] && [ ! -L "$installed" ] && \
        cmp -s "$snapshot_directory/$unit" "$installed" || \
        recovery_failure "install recovery refuses changed unit $unit"
    fi
  done
  install_timers='vps-guardian-backup.timer'
  if [ "$snapshot_has_freshness" = 'true' ]; then
    install_timers="$install_timers vps-guardian-backup-freshness.timer"
  fi
  systemctl disable vps-guardian-controller.service $install_timers >/dev/null 2>&1 || true
  systemctl stop vps-guardian-backup.service \
    vps-guardian-backup-freshness.service >/dev/null 2>&1 || true
  if [ -L /opt/vps-guardian/current ]; then
    rm -f -- /opt/vps-guardian/current || recovery_failure 'install current link could not be removed'
  fi
  for unit in $snapshot_systemd_units; do
    rm -f -- "/etc/systemd/system/$unit" || \
      recovery_failure "install unit $unit could not be removed"
  done
  committed_marker="$snapshot_directory/COMMITTED"
  if [ -e "$committed_marker" ] || [ -L "$committed_marker" ]; then
    committed_value=''
    [ -f "$committed_marker" ] && [ ! -L "$committed_marker" ] && \
      [ "$(stat -c '%U:%G:%a' -- "$committed_marker")" = 'root:root:400' ] && \
      IFS= read -r committed_value < "$committed_marker" && \
      [ "$committed_value" = "$candidate_release" ] || \
      recovery_failure 'install COMMITTED marker is unsafe'
    rm -f -- "$committed_marker" || recovery_failure 'install COMMITTED marker could not be removed'
  fi
  systemctl daemon-reload || recovery_failure 'systemd could not reload after install recovery'
  lifecycle_journal update --phase aborted --controller-state inactive \
    --timer-state inactive >/dev/null || recovery_failure 'install recovery could not be completed'
  lifecycle_journal clear || recovery_failure 'install recovery journal could not be cleared'
  echo 'recovered and cleared the interrupted fresh installation'
  exit 0
fi

previous_release="$(journal_field previous_release)"
previous_id="$(direct_release_id "$previous_release")" || \
  recovery_failure 'journal previous release is not a direct release child'
[ "$previous_id" != "$candidate_id" ] || recovery_failure 'journal releases are identical'
validate_previous_release "$previous_release" || \
  recovery_failure 'previous release is missing, mutable, or incomplete'
validate_current_target "$previous_release" "$candidate_release" || \
  recovery_failure 'current link does not match either journal release'
snapshot_directory="$(journal_unit_directory)" || \
  recovery_failure 'journal has invalid unit snapshot references'
if [ "$operation" = 'upgrade' ]; then
  [ "$snapshot_directory" = "/var/backups/vps-guardian-controller/$candidate_id/systemd" ] || \
    recovery_failure 'upgrade journal unit snapshots do not match the candidate transaction'
else
  rollback_prefix='/var/backups/vps-guardian-controller/rollback-'
  case "$snapshot_directory" in
    "$rollback_prefix"*/systemd)
      rollback_component="${snapshot_directory#"$rollback_prefix"}"
      rollback_component="${rollback_component%/systemd}"
      case "$rollback_component" in ''|*/*|.|..) recovery_failure 'rollback snapshot path is not direct' ;; esac
      ;;
    *) recovery_failure 'rollback journal unit snapshots are outside the transaction root' ;;
  esac
fi
validate_snapshot_directory "$snapshot_directory" "$snapshot_systemd_units" || \
  recovery_failure 'previous unit snapshot is missing or unsafe'

if [ "$snapshot_has_freshness" != 'true' ]; then
  if [ -e /etc/systemd/system/vps-guardian-backup-freshness.timer ] || \
     [ -L /etc/systemd/system/vps-guardian-backup-freshness.timer ]; then
    systemctl disable vps-guardian-backup-freshness.timer || \
      recovery_failure 'candidate freshness timer could not be disabled'
  fi
  for unit in $freshness_systemd_units; do
    rm -f -- "/etc/systemd/system/$unit" || \
      recovery_failure "candidate freshness unit $unit could not be removed"
  done
fi
for unit in $snapshot_systemd_units; do
  install -o root -g root -m 0644 "$snapshot_directory/$unit" \
    "/etc/systemd/system/$unit" || recovery_failure "previous unit $unit could not be restored"
done
systemctl daemon-reload || recovery_failure 'systemd could not reload previous units'
switch_current "$previous_release" || recovery_failure 'previous release link could not be restored'
validate_controller_inputs || recovery_failure 'Controller inputs are unsafe for offline verification'
if ! verify_release_offline "$previous_release"; then
  recovery_failure 'previous release is incompatible with the live schema; database recovery is required'
fi
if ! systemctl restart vps-guardian-controller.service || \
   ! verify_running_release "$previous_release"; then
  recovery_failure 'previous Controller failed runtime verification'
fi
if ! restore_timer_state "$timer_state" "$snapshot_has_freshness"; then
  recovery_failure 'backup timer initial state could not be restored'
fi
trap 'exit 75' HUP INT TERM
lifecycle_journal update --phase previous_restored --controller-state active \
  --timer-state "$timer_state" >/dev/null || \
  recovery_failure 'previous release restoration could not be persisted'
if ! lifecycle_journal clear; then
  echo 'recovered lifecycle journal could not be cleared; restored runtime left active' >&2
  exit 72
fi
printf 'recovered and cleared the interrupted %s\n' "$operation"
