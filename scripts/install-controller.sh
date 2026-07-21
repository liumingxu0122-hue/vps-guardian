#!/bin/sh
set -eu

source_dir=''
execute='false'
initialize_restic='false'
restic_confirmation=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) source_dir="$2"; shift 2 ;;
    --execute) execute='true'; shift ;;
    --initialize-restic) initialize_restic='true'; shift ;;
    --confirm-restic) restic_confirmation="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then echo "installation must run as root" >&2; exit 77; fi
core_systemd_units='vps-guardian-controller.service vps-guardian-backup.service vps-guardian-backup.timer'
freshness_systemd_units='vps-guardian-backup-freshness.service vps-guardian-backup-freshness.timer'
managed_systemd_units="$core_systemd_units $freshness_systemd_units"
if [ "$execute" != 'true' ]; then
  echo "usage: $0 --source RELEASE_DIRECTORY --execute [--initialize-restic --confirm-restic 'INITIALIZE RESTIC REPOSITORY']" >&2
  exit 64
fi
if { [ "$initialize_restic" = 'true' ] && \
     [ "$restic_confirmation" != 'INITIALIZE RESTIC REPOSITORY' ]; } || \
   { [ "$initialize_restic" != 'true' ] && [ -n "$restic_confirmation" ]; }; then
  echo "Restic initialization requires both --initialize-restic and exact confirmation" >&2
  exit 64
fi
for command in cmp curl dirname find flock getent git gpasswd grep groupadd install \
  mktemp npm python3 readlink sha256sum sort stat tar useradd usermod xargs; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 69; }
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
  echo "installer script directory cannot be resolved" >&2
  exit 66
}
journal_tool="$script_dir/lifecycle-journal.py"
[ -f "$journal_tool" ] && [ ! -L "$journal_tool" ] && \
  [ "$(readlink -f -- "$journal_tool")" = "$journal_tool" ] || {
  echo "installer has no trusted lifecycle journal helper" >&2
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
  echo "installer has no trusted controller recovery helper" >&2
  exit 66
}
run_lifecycle_recovery() {
  sh "$recovery_helper" --expected-operation install --lock-fd 9
}
if [ -e "$journal_file" ] || [ -L "$journal_file" ]; then
  exec sh "$recovery_helper" --expected-operation install --lock-fd 9
fi
controller_env='/etc/vps-guardian/controller.env'
if [ ! -f "$controller_env" ] || [ -L "$controller_env" ] || \
   [ "$(readlink -f -- "$controller_env")" != "$controller_env" ] || \
   [ "$(stat -c '%U:%G:%a' "$controller_env")" != 'root:root:600' ]; then
  echo "$controller_env must be a root-owned regular file with mode 0600" >&2
  exit 66
fi
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
if [ -z "$source_dir" ] || [ ! -f "$source_dir/pyproject.toml" ] || \
   [ ! -f "$source_dir/web/package-lock.json" ]; then
  echo "source directory is not a VPS Guardian release" >&2
  exit 65
fi
source_canonical="$(readlink -f -- "$source_dir")" || {
  echo "release source cannot be resolved" >&2
  exit 65
}
source_git_root="$(git -C "$source_canonical" rev-parse --show-toplevel 2>/dev/null)" || {
  echo "release source must be a Git worktree" >&2
  exit 65
}
[ "$source_git_root" = "$source_canonical" ] || {
  echo "release source must be the root of its Git worktree" >&2
  exit 65
}
source_commit="$(git -C "$source_git_root" rev-parse --verify 'HEAD^{commit}')" || {
  echo "release source HEAD is not a commit" >&2
  exit 65
}
case "$source_commit" in
  *[!0-9a-f]*|'') echo "release source commit is invalid" >&2; exit 65 ;;
esac
source_status="$(git -C "$source_git_root" status --porcelain=v1 --untracked-files=all)" || {
  echo "release source status could not be read" >&2
  exit 65
}
if [ -n "$source_status" ]; then
  echo "release source must be a clean Git worktree" >&2
  exit 73
fi
source_dir="$source_git_root"
manifest_tool="$source_dir/scripts/release-manifest.py"
[ -f "$manifest_tool" ] && [ ! -L "$manifest_tool" ] || {
  echo "release source is missing the exact manifest verifier" >&2
  exit 66
}
if [ -e /opt/vps-guardian/current ] || [ -L /opt/vps-guardian/current ]; then
  echo "controller is already installed; use upgrade-controller.sh" >&2
  exit 73
fi

getent group guardian >/dev/null 2>&1 || groupadd --system guardian
id guardian >/dev/null 2>&1 || useradd --system --gid guardian --home-dir /var/lib/vps-guardian --shell /usr/sbin/nologin guardian
getent group guardian-release >/dev/null 2>&1 || groupadd --system guardian-release
getent group guardian-database >/dev/null 2>&1 || groupadd --system guardian-database
usermod -a -G guardian-release,guardian-database guardian
getent group guardian-backup >/dev/null 2>&1 || groupadd --system guardian-backup
id guardian-backup >/dev/null 2>&1 || useradd --system --gid guardian-backup \
  --groups guardian-release,guardian-database --home-dir /var/lib/vps-guardian-backup \
  --shell /usr/sbin/nologin \
  guardian-backup
usermod -g guardian-backup -a -G guardian-release,guardian-database guardian-backup
gpasswd -d guardian-backup guardian >/dev/null 2>&1 || true
for service_user in guardian guardian-backup; do
  for service_group in guardian-release guardian-database; do
    id -nG "$service_user" | tr ' ' '\n' | grep -Fx "$service_group" >/dev/null || {
      echo "$service_user must belong to $service_group" >&2
      exit 77
    }
  done
done
if id -nG guardian-backup | tr ' ' '\n' | grep -Fx guardian >/dev/null; then
  echo "guardian-backup must not belong to the guardian private-key group" >&2
  exit 77
fi
controller_database_url='/etc/vps-guardian/database-url'
[ -d /etc/vps-guardian ] && [ ! -L /etc/vps-guardian ] && \
  [ "$(readlink -f -- /etc/vps-guardian)" = '/etc/vps-guardian' ] && \
  [ "$(stat -c '%U:%G:%a' -- /etc/vps-guardian)" = 'root:guardian-database:750' ] || {
    echo "/etc/vps-guardian must be root:guardian-database with mode 0750" >&2
    exit 77
  }
[ -f "$controller_database_url" ] && [ ! -L "$controller_database_url" ] && \
  [ "$(readlink -f -- "$controller_database_url")" = "$controller_database_url" ] && \
  [ -s "$controller_database_url" ] && \
  [ "$(stat -c '%U:%G:%a' "$controller_database_url")" = 'root:guardian-database:640' ] || {
    echo "$controller_database_url must be root:guardian-database with mode 0640" >&2
    exit 77
  }
controller_signing_key='/etc/vps-guardian/controller-ed25519.pem'
[ -f "$controller_signing_key" ] && [ ! -L "$controller_signing_key" ] && \
  [ "$(readlink -f -- "$controller_signing_key")" = "$controller_signing_key" ] && \
  [ -s "$controller_signing_key" ] && \
  [ "$(stat -c '%U:%G:%a' "$controller_signing_key")" = 'root:guardian:640' ] || {
    echo "$controller_signing_key must be root:guardian with mode 0640" >&2
    exit 77
  }
backup_secrets='/etc/vps-guardian-backup-secrets'
[ -d "$backup_secrets" ] && [ ! -L "$backup_secrets" ] && \
  [ "$(readlink -f -- "$backup_secrets")" = "$backup_secrets" ] && \
  [ "$(stat -c '%U:%G:%a' "$backup_secrets")" = 'root:guardian-backup:750' ] || {
    echo "$backup_secrets must be root:guardian-backup with mode 0750" >&2
    exit 77
  }
obsolete_backup_database_url="$backup_secrets/database-url"
[ ! -e "$obsolete_backup_database_url" ] && [ ! -L "$obsolete_backup_database_url" ] || {
  echo "$obsolete_backup_database_url is obsolete; remove the duplicate database URL" >&2
  exit 77
}
for name in restic-repository restic-password; do
  [ -f "$backup_secrets/$name" ] && [ ! -L "$backup_secrets/$name" ] && \
    [ "$(readlink -f -- "$backup_secrets/$name")" = "$backup_secrets/$name" ] && \
    [ -s "$backup_secrets/$name" ] && \
    [ "$(stat -c '%U:%G:%a' "$backup_secrets/$name")" = 'root:guardian-backup:640' ] || {
      echo "required backup Secret must be root:guardian-backup with mode 0640: $name" >&2
      exit 77
    }
done
read_controlled_value() {
  python3 - "$1" <<'PY'
import sys
import unicodedata
from pathlib import Path

try:
    payload = Path(sys.argv[1]).read_bytes()
    if not 0 < len(payload) <= 4096:
        raise ValueError
    text = payload.decode("utf-8")
    value = text[:-2] if text.endswith("\r\n") else text[:-1] if text.endswith("\n") else text
    if (
        not value
        or value != value.strip()
        or any(char.isspace() or unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValueError
except (OSError, UnicodeError, ValueError):
    raise SystemExit(1)
print(value, end="")
PY
}
restic_repository="$(read_controlled_value "$backup_secrets/restic-repository")" || {
  echo "Restic repository file contains an invalid value" >&2
  exit 77
}
case "$restic_repository" in
  s3:*)
    for name in aws-access-key-id aws-secret-access-key aws-region; do
      [ -f "$backup_secrets/$name" ] && [ ! -L "$backup_secrets/$name" ] && \
        [ "$(readlink -f -- "$backup_secrets/$name")" = "$backup_secrets/$name" ] && \
        [ -s "$backup_secrets/$name" ] && \
        [ "$(stat -c '%U:%G:%a' "$backup_secrets/$name")" = 'root:guardian-backup:640' ] || {
          echo "required S3 Secret must be root:guardian-backup with mode 0640: $name" >&2
          exit 77
        }
    done
    ;;
  /*)
    canonical_repository="$(readlink -m -- "$restic_repository")" || exit 77
    [ "$canonical_repository" = "$restic_repository" ] && \
      { [ "$restic_repository" = '/var/lib/vps-guardian-backup/restic' ] || \
        case "$restic_repository" in /var/lib/vps-guardian-backup/restic/*) true ;; *) false ;; esac; } || {
      echo "systemd local Restic repositories must be canonical paths under /var/lib/vps-guardian-backup/restic" >&2
      exit 77
    }
    unset canonical_repository
    ;;
  *)
    echo "systemd local Restic repositories must be under /var/lib/vps-guardian-backup/restic" >&2
    exit 77
    ;;
esac
unset restic_repository
(
  unset GUARDIAN_DATABASE_URL
  set -a
  . "$controller_env"
  set +a
  controller_database_url_value="$(read_controlled_value "$controller_database_url")" || exit 1
  [ -z "${GUARDIAN_DATABASE_URL:-}" ] || \
    [ "$GUARDIAN_DATABASE_URL" = "$controller_database_url_value" ]
) || {
  echo "the legacy database URL must match the fixed database URL file" >&2
  exit 77
}
install_root='/opt/vps-guardian'
releases_root="$install_root/releases"
[ -d /opt ] && [ ! -L /opt ] && [ "$(readlink -f -- /opt)" = '/opt' ] && \
  [ "$(stat -c '%U:%G:%a' -- /opt)" = 'root:root:755' ] || {
  echo "/opt must be a root-owned regular directory with mode 0755" >&2
  exit 77
}
if [ -e "$install_root" ] || [ -L "$install_root" ]; then
  [ -d "$install_root" ] && [ ! -L "$install_root" ] && \
    [ "$(readlink -f -- "$install_root")" = "$install_root" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$install_root")" = 'root:root:755' ] || {
    echo "$install_root must be root-owned with mode 0755" >&2
    exit 77
  }
else
  install -d -o root -g root -m 0755 "$install_root"
fi
if [ -e "$releases_root" ] || [ -L "$releases_root" ]; then
  [ -d "$releases_root" ] && [ ! -L "$releases_root" ] && \
    [ "$(readlink -f -- "$releases_root")" = "$releases_root" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$releases_root")" = 'root:root:755' ] || {
    echo "$releases_root must be root-owned with mode 0755" >&2
    exit 77
  }
else
  install -d -o root -g root -m 0755 "$releases_root"
fi
install -d -o guardian -g guardian -m 0750 \
  /var/lib/vps-guardian /var/log/vps-guardian
install -d -o guardian-backup -g guardian-backup -m 0750 \
  /var/lib/vps-guardian-backup /var/lib/vps-guardian-backup/restic \
  /var/cache/vps-guardian-backup
unit_store_root='/var/lib/vps-guardian-units'
if [ -e "$unit_store_root" ] || [ -L "$unit_store_root" ]; then
  [ -d "$unit_store_root" ] && [ ! -L "$unit_store_root" ] && \
    [ "$(readlink -f -- "$unit_store_root")" = "$unit_store_root" ] && \
    [ "$(stat -c '%U:%G:%a' "$unit_store_root")" = 'root:root:755' ] || {
    echo "$unit_store_root must be root-owned with mode 0755" >&2
    exit 77
  }
else
  install -d -o root -g root -m 0755 "$unit_store_root"
fi
release_id="$(date -u +%Y%m%dT%H%M%SZ)"
release_dir="$releases_root/$release_id"
unit_store="$unit_store_root/$release_id"
reject_release_symlinks() {
  symlink_path="$(find "$release_dir" -type l -print -quit)"
  [ -z "$symlink_path" ] || {
    echo "release contains a symbolic link: $symlink_path" >&2
    return 1
  }
}
remove_node_modules_tree() {
  node_modules="$release_dir/web/node_modules"
  [ -d "$node_modules" ] && [ ! -L "$node_modules" ] && \
    [ "$(readlink -f -- "$node_modules")" = "$node_modules" ] || {
    echo "web dependency tree is missing or unsafe" >&2
    return 1
  }
  find "$node_modules" -depth -delete
  [ ! -e "$node_modules" ] && [ ! -L "$node_modules" ]
}
for new_path in "$release_dir" "$unit_store"; do
  [ ! -e "$new_path" ] && [ ! -L "$new_path" ] || {
    echo "installation transaction path already exists: $new_path" >&2
    exit 73
  }
done
for unit in $managed_systemd_units; do
  unit_path="/etc/systemd/system/$unit"
  [ ! -e "$unit_path" ] && [ ! -L "$unit_path" ] || {
    echo "systemd unit already exists on a fresh installation: $unit" >&2
    exit 73
  }
done
install -d -o root -g root -m 0700 "$release_dir"
release_archive="$release_dir/.reviewed-source.tar"
git -C "$source_dir" archive --format=tar --output="$release_archive" \
  "$source_commit" -- controller deploy/systemd runbooks scripts web \
  README.md pyproject.toml requirements-build.lock requirements.lock
(cd "$release_dir" && umask 022 && \
  tar --no-same-owner --no-same-permissions -xf "$release_archive")
rm -f -- "$release_archive"
printf '%s\n' "$source_commit" > "$release_dir/SOURCE_COMMIT"
reject_release_symlinks
install -d -o root -g root -m 0700 "$unit_store"
[ -d "$release_dir/deploy/systemd" ] && [ ! -L "$release_dir/deploy" ] && \
  [ ! -L "$release_dir/deploy/systemd" ] || {
  echo "release systemd directory is missing or unsafe" >&2
  exit 66
}
for unit in $managed_systemd_units; do
  unit_source="$release_dir/deploy/systemd/$unit"
  [ -f "$unit_source" ] && [ ! -L "$unit_source" ] || {
    echo "release is missing a regular systemd unit: $unit" >&2
    exit 66
  }
  install -o root -g root -m 0644 "$unit_source" "$unit_store/$unit"
done
chown -R guardian:guardian "$release_dir"
chmod 0750 "$release_dir"
su -s /bin/sh guardian -c "python3 -m venv --copies '$release_dir/.venv' && \
  '$release_dir/.venv/bin/pip' install --disable-pip-version-check --no-cache-dir \
    --require-hashes -r '$release_dir/requirements-build.lock' && \
  '$release_dir/.venv/bin/pip' install --disable-pip-version-check --no-cache-dir \
    --require-hashes -r '$release_dir/requirements.lock' && \
  '$release_dir/.venv/bin/pip' install --disable-pip-version-check --no-cache-dir \
    --no-build-isolation --no-deps '$release_dir'"
su -s /bin/sh guardian -c "cd '$release_dir/web' && \
  npm ci --ignore-scripts && npm run build"
remove_node_modules_tree
reject_release_symlinks
chown -hR root:guardian-release "$release_dir"
find "$release_dir" -type d -exec chmod 0550 {} \;
find "$release_dir" -type f -perm /111 -exec chmod 0550 {} \;
find "$release_dir" -type f ! -perm /111 -exec chmod 0440 {} \;
release_manifest="$unit_store/RELEASE.MANIFEST.json"
manifest_tmp="$(mktemp "$unit_store/.RELEASE.MANIFEST.XXXXXX")"
python3 "$manifest_tool" write "$release_dir" "$manifest_tmp"
chown root:root -- "$manifest_tmp"
chmod 0400 -- "$manifest_tmp"
mv -Tf "$manifest_tmp" "$release_manifest"
python3 "$manifest_tool" verify "$release_dir" "$release_manifest"
backup_runner="$release_dir/scripts/run-backup-command.sh"
if [ "$initialize_restic" = 'true' ]; then
  su -s /bin/sh guardian-backup -c \
    "sh '$backup_runner' guardian-backup repository-init --execute --confirm 'INITIALIZE RESTIC REPOSITORY'"
fi
su -s /bin/sh guardian-backup -c \
  "sh '$backup_runner' guardian-backup repository-check --read-data-subset 5%"

unset GUARDIAN_DATABASE_URL
set -a
. "$controller_env"
set +a
export GUARDIAN_DATABASE_URL_FILE="$controller_database_url"
export GUARDIAN_CONTROLLER_SIGNING_KEY_FILE="$controller_signing_key"
journal_active='false'
installation_committed='false'
cleanup_failed_installation() {
  exit_status=$?
  trap - EXIT
  if [ "$journal_active" = 'true' ] && [ "$installation_committed" != 'true' ]; then
    if ! run_lifecycle_recovery; then
      echo "fresh installation failed and durable recovery could not complete" >&2
      exit_status=72
    fi
  fi
  exit "$exit_status"
}
trap cleanup_failed_installation EXIT
trap 'exit 75' HUP INT TERM
service_state() {
  if systemctl is-active --quiet "$1"; then
    printf 'active\n'
  elif systemctl is-failed --quiet "$1"; then
    printf 'failed\n'
  else
    printf 'inactive\n'
  fi
}
database_revision() {
  revision_release="$1"
  su -s /bin/sh guardian -c \
    "cd '$revision_release' && '$revision_release/.venv/bin/python' -c 'from alembic.migration import MigrationContext; from guardian.database import engine; connection = engine.connect(); heads = MigrationContext.configure(connection).get_current_heads(); print(\"+\".join(heads) if heads else \"base\"); connection.close()'"
}
db_revision_before="$(database_revision "$release_dir")"
controller_initial_state="$(service_state vps-guardian-controller.service)"
timer_initial_state="$(service_state vps-guardian-backup.timer)"
lifecycle_journal init --operation install --candidate-release "$release_dir" \
  --db-revision-before "$db_revision_before" \
  --unit-metadata-ref "$unit_store/vps-guardian-controller.service" \
  --unit-metadata-ref "$unit_store/vps-guardian-backup.service" \
  --unit-metadata-ref "$unit_store/vps-guardian-backup.timer" \
  --unit-metadata-ref "$unit_store/vps-guardian-backup-freshness.service" \
  --unit-metadata-ref "$unit_store/vps-guardian-backup-freshness.timer" \
  --timer-state "$timer_initial_state" \
  --controller-state "$controller_initial_state" >/dev/null
journal_active='true'
lifecycle_journal update --phase prepared >/dev/null
# prepared is durable before the Alembic boundary.
su -s /bin/sh guardian -c \
  "cd '$release_dir' && '$release_dir/.venv/bin/alembic' -c controller/alembic.ini upgrade head"
db_revision_after="$(database_revision "$release_dir")"
lifecycle_journal update --phase database_updated \
  --db-revision-after "$db_revision_after" >/dev/null
for unit in $managed_systemd_units; do
  install -o root -g root -m 0644 "$unit_store/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
lifecycle_journal update --phase units_updated >/dev/null
ln -s "$release_dir" "$install_root/current"
lifecycle_journal update --phase candidate_activated >/dev/null
systemctl enable --now vps-guardian-controller.service
curl --fail --silent --show-error --retry 10 --retry-delay 2 http://127.0.0.1:8090/health >/dev/null
curl --fail --silent --show-error --retry 10 --retry-delay 2 http://127.0.0.1:8090/ready >/dev/null
su -s /bin/sh guardian -c \
  "cd '$release_dir' && '$release_dir/.venv/bin/alembic' -c controller/alembic.ini current --check-heads"
lifecycle_journal update --phase verified --controller-state active >/dev/null
systemctl enable --now vps-guardian-backup.timer vps-guardian-backup-freshness.timer
for timer in vps-guardian-backup.timer vps-guardian-backup-freshness.timer; do
  systemctl is-active --quiet "$timer"
done
reject_release_symlinks
python3 "$manifest_tool" verify "$release_dir" "$release_manifest"
committed_tmp="$(mktemp "$unit_store/.COMMITTED.XXXXXX")"
printf '%s\n' "$release_dir" > "$committed_tmp"
chown root:root -- "$committed_tmp"
chmod 0400 -- "$committed_tmp"
mv -Tf "$committed_tmp" "$unit_store/COMMITTED"
lifecycle_journal update --phase committed --controller-state active \
  --timer-state active >/dev/null
installation_committed='true'
lifecycle_journal clear
journal_active='false'
printf 'installed controller release %s\n' "$release_id"
