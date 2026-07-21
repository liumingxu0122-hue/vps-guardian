#!/bin/sh
set -eu

source_dir=''
approval_id=''
confirmation=''
execute='false'
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) source_dir="$2"; shift 2 ;;
    --approval-id) approval_id="$2"; shift 2 ;;
    --confirm) confirmation="$2"; shift 2 ;;
    --execute) execute='true'; shift ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then echo "upgrade must run as root" >&2; exit 77; fi
core_systemd_units='vps-guardian-controller.service vps-guardian-backup.service vps-guardian-backup.timer'
freshness_systemd_units='vps-guardian-backup-freshness.service vps-guardian-backup-freshness.timer'
managed_systemd_units="$core_systemd_units $freshness_systemd_units"
if [ "$execute" != 'true' ] || [ -z "$approval_id" ] || [ "$confirmation" != 'UPGRADE VPS GUARDIAN' ]; then
  echo "upgrade requires --execute, --approval-id, and --confirm 'UPGRADE VPS GUARDIAN'" >&2
  exit 64
fi
for command in cmp curl dirname find flock getent git gpasswd grep groupadd install \
  mktemp npm python3 readlink sha256sum stat tar useradd usermod; do
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
  echo "upgrade script directory cannot be resolved" >&2
  exit 66
}
journal_tool="$script_dir/lifecycle-journal.py"
[ -f "$journal_tool" ] && [ ! -L "$journal_tool" ] && \
  [ "$(readlink -f -- "$journal_tool")" = "$journal_tool" ] || {
  echo "upgrade script has no trusted lifecycle journal helper" >&2
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
  echo "upgrade script has no trusted controller recovery helper" >&2
  exit 66
}
run_lifecycle_recovery() {
  sh "$recovery_helper" --expected-operation upgrade --lock-fd 9
}
if [ -e "$journal_file" ] || [ -L "$journal_file" ]; then
  exec sh "$recovery_helper" --expected-operation upgrade --lock-fd 9
fi
if [ -z "$source_dir" ] || [ ! -f "$source_dir/pyproject.toml" ]; then
  echo "invalid release source or current installation" >&2
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
service_state() {
  if systemctl is-active --quiet "$1"; then
    printf 'active\n'
  elif systemctl is-failed --quiet "$1"; then
    printf 'failed\n'
  else
    printf 'inactive\n'
  fi
}
controller_env='/etc/vps-guardian/controller.env'
[ -f "$controller_env" ] && [ ! -L "$controller_env" ] && \
  [ "$(readlink -f -- "$controller_env")" = "$controller_env" ] && \
  [ "$(stat -c '%U:%G:%a' "$controller_env")" = 'root:root:600' ] || {
  echo "$controller_env must be a root-owned regular file with mode 0600" >&2
  exit 66
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
id guardian >/dev/null 2>&1 || {
  echo "guardian service account is missing" >&2
  exit 77
}
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
case "$(stat -c '%U:%G:%a' -- /etc/vps-guardian 2>/dev/null || true)" in
  root:guardian-database:750) ;;
  root:root:700)
    [ -f "$controller_database_url" ] && [ ! -L "$controller_database_url" ] && \
      [ "$(readlink -f -- "$controller_database_url")" = "$controller_database_url" ] && \
      [ -s "$controller_database_url" ] && \
      [ "$(stat -c '%U:%G:%a' -- "$controller_database_url")" = \
        'root:guardian:640' ] || {
      echo "legacy Controller database URL cannot be migrated safely" >&2
      exit 77
    }
    chown root:guardian-database -- "$controller_database_url" /etc/vps-guardian
    chmod 0750 -- /etc/vps-guardian
    ;;
esac
[ -d /etc/vps-guardian ] && [ ! -L /etc/vps-guardian ] && \
  [ "$(readlink -f -- /etc/vps-guardian)" = '/etc/vps-guardian' ] && \
  [ "$(stat -c '%U:%G:%a' -- /etc/vps-guardian)" = 'root:guardian-database:750' ] || {
  echo "/etc/vps-guardian must be root:guardian-database with mode 0750" >&2
  exit 77
}
[ -f "$controller_database_url" ] && [ ! -L "$controller_database_url" ] && \
  [ "$(readlink -f -- "$controller_database_url")" = "$controller_database_url" ] && \
  [ -s "$controller_database_url" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$controller_database_url")" = 'root:guardian-database:640' ] || {
  echo "$controller_database_url must be root:guardian-database with mode 0640" >&2
  exit 77
}
controller_signing_key='/etc/vps-guardian/controller-ed25519.pem'
[ -f "$controller_signing_key" ] && [ ! -L "$controller_signing_key" ] && \
  [ "$(readlink -f -- "$controller_signing_key")" = "$controller_signing_key" ] && \
  [ -s "$controller_signing_key" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$controller_signing_key")" = 'root:guardian:640' ] || {
  echo "$controller_signing_key must be root:guardian with mode 0640" >&2
  exit 77
}
backup_secrets='/etc/vps-guardian-backup-secrets'
[ -d "$backup_secrets" ] && [ ! -L "$backup_secrets" ] && \
  [ "$(readlink -f -- "$backup_secrets")" = "$backup_secrets" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$backup_secrets")" = 'root:guardian-backup:750' ] || {
  echo "$backup_secrets must be root:guardian-backup with mode 0750" >&2
  exit 77
}
obsolete_backup_database_url="$backup_secrets/database-url"
if [ -e "$obsolete_backup_database_url" ] || [ -L "$obsolete_backup_database_url" ]; then
  [ -f "$obsolete_backup_database_url" ] && [ ! -L "$obsolete_backup_database_url" ] && \
    [ "$(readlink -f -- "$obsolete_backup_database_url")" = \
      "$obsolete_backup_database_url" ] && \
    [ -s "$obsolete_backup_database_url" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$obsolete_backup_database_url")" = \
      'root:guardian-backup:640' ] && \
    cmp -s "$controller_database_url" "$obsolete_backup_database_url" || {
    echo "obsolete backup database URL is unsafe or differs from the fixed database URL" >&2
    exit 77
  }
  rm -f -- "$obsolete_backup_database_url"
fi
for name in restic-repository restic-password; do
  secret_path="$backup_secrets/$name"
  [ -f "$secret_path" ] && [ ! -L "$secret_path" ] && \
    [ "$(readlink -f -- "$secret_path")" = "$secret_path" ] && \
    [ -s "$secret_path" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$secret_path")" = 'root:guardian-backup:640' ] || {
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
      secret_path="$backup_secrets/$name"
      [ -f "$secret_path" ] && [ ! -L "$secret_path" ] && \
        [ "$(readlink -f -- "$secret_path")" = "$secret_path" ] && \
        [ -s "$secret_path" ] && \
      [ "$(stat -c '%U:%G:%a' -- "$secret_path")" = 'root:guardian-backup:640' ] || {
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
current_link="$install_root/current"
[ -d /opt ] && [ ! -L /opt ] && [ "$(readlink -f -- /opt)" = '/opt' ] && \
  [ "$(stat -c '%U:%G:%a' -- /opt)" = 'root:root:755' ] || {
  echo "/opt must be a root-owned regular directory with mode 0755" >&2
  exit 77
}
[ -d "$install_root" ] && [ ! -L "$install_root" ] && \
  [ "$(readlink -f -- "$install_root")" = "$install_root" ] || {
  echo "$install_root must be a regular directory without symbolic-link components" >&2
  exit 77
}

# The legacy installer assigned these directory entries to guardian. Freeze the
# parent first, then the release root, and never trust units from an old release.
case "$(stat -c '%U:%G:%a' -- "$install_root")" in
  root:root:755) ;;
  root:root:750)
    chmod 0755 -- "$install_root"
    ;;
  guardian:guardian:750)
    [ -L "$current_link" ] && \
      [ "$(stat -c '%U:%G' -- "$current_link")" = 'root:root' ] && \
      [ -d "$releases_root" ] && [ ! -L "$releases_root" ] && \
      [ "$(stat -c '%U:%G:%a' -- "$releases_root")" = 'guardian:guardian:750' ] || {
      echo "legacy installation layout is not safe to migrate" >&2
      exit 77
    }
    chown root:root -- "$install_root"
    chmod 0755 -- "$install_root"
    ;;
  *)
    echo "$install_root must be root:root:0755/0750 or the exact guardian:guardian:0750 legacy layout" >&2
    exit 77
    ;;
esac
[ -d "$install_root" ] && [ ! -L "$install_root" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$install_root")" = 'root:root:755' ] && \
  [ -L "$current_link" ] && \
  [ "$(stat -c '%U:%G' -- "$current_link")" = 'root:root' ] || {
  echo "$install_root ownership migration did not produce a trusted layout" >&2
  exit 77
}

[ -d "$releases_root" ] && [ ! -L "$releases_root" ] && \
  [ "$(readlink -f -- "$releases_root")" = "$releases_root" ] || {
  echo "$releases_root must be a regular directory without symbolic-link components" >&2
  exit 77
}
case "$(stat -c '%U:%G:%a' -- "$releases_root")" in
  root:root:755) ;;
  root:root:750)
    chmod 0755 -- "$releases_root"
    ;;
  guardian:guardian:750)
    chown root:root -- "$releases_root"
    chmod 0755 -- "$releases_root"
    ;;
  *)
    echo "$releases_root must be root:root:0755/0750 or the exact guardian:guardian:0750 legacy layout" >&2
    exit 77
    ;;
esac
[ -d "$releases_root" ] && [ ! -L "$releases_root" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$releases_root")" = 'root:root:755' ] || {
  echo "$releases_root ownership migration did not produce a trusted layout" >&2
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
current="$(readlink -f -- "$current_raw")" || {
  echo "current release cannot be resolved" >&2
  exit 65
}
[ "$current" = "$current_raw" ] || {
  echo "current release cannot contain symbolic-link path components" >&2
  exit 65
}

# The service namespace already treats /opt as read-only. Make that invariant
# true on disk before any candidate build process can reach rollback code.
chown -hR root:guardian-release "$current"
find "$current" -type d -exec chmod 0550 {} \;
find "$current" -type f -perm /111 -exec chmod 0550 {} \;
find "$current" -type f ! -perm /111 -exec chmod 0440 {} \;

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
  backup_dir="/var/backups/vps-guardian-controller/$release_id"
  candidate_unit_store="$unit_store_root/$release_id"
  for new_path in "$release_dir" "$backup_dir" "$candidate_unit_store"; do
    [ ! -e "$new_path" ] && [ ! -L "$new_path" ] || {
      echo "upgrade transaction path already exists: $new_path" >&2
      exit 73
    }
  done
  install -d -o root -g root -m 0700 "$backup_dir"
  unit_backup_dir="$backup_dir/systemd"
  install -d -o root -g root -m 0700 "$unit_backup_dir"
  installed_systemd_units="$core_systemd_units"
  freshness_service_exists='false'
  freshness_timer_exists='false'
  if [ -e /etc/systemd/system/vps-guardian-backup-freshness.service ] || \
     [ -L /etc/systemd/system/vps-guardian-backup-freshness.service ]; then
    freshness_service_exists='true'
  fi
  if [ -e /etc/systemd/system/vps-guardian-backup-freshness.timer ] || \
     [ -L /etc/systemd/system/vps-guardian-backup-freshness.timer ]; then
    freshness_timer_exists='true'
  fi
  [ "$freshness_service_exists" = "$freshness_timer_exists" ] || {
    echo 'installed systemd freshness unit set is incomplete' >&2
    exit 66
  }
  if [ "$freshness_service_exists" = 'true' ]; then
    installed_systemd_units="$managed_systemd_units"
  fi
  for unit in $installed_systemd_units; do
    unit_path="/etc/systemd/system/$unit"
    [ -f "$unit_path" ] && [ ! -L "$unit_path" ] && \
      [ "$(readlink -f -- "$unit_path")" = "$unit_path" ] && \
      [ "$(stat -c '%U:%G:%a' -- "$unit_path")" = 'root:root:644' ] || {
      echo "installed systemd unit is missing or unsafe: $unit" >&2
      exit 66
    }
    cp -p "$unit_path" "$unit_backup_dir/$unit"
  done
  current_unit_store="$unit_store_root/$current_release_id"
  if [ -e "$current_unit_store" ] || [ -L "$current_unit_store" ]; then
    [ -d "$current_unit_store" ] && [ ! -L "$current_unit_store" ] && \
      [ "$(readlink -f -- "$current_unit_store")" = "$current_unit_store" ] && \
      [ "$(stat -c '%U:%G:%a' "$current_unit_store")" = 'root:root:700' ] || {
      echo "$current_unit_store must be root-owned with mode 0700" >&2
      exit 77
    }
    for unit in $installed_systemd_units; do
      unit_snapshot="$current_unit_store/$unit"
      [ -f "$unit_snapshot" ] && [ ! -L "$unit_snapshot" ] && \
        [ "$(readlink -f -- "$unit_snapshot")" = "$unit_snapshot" ] && \
        [ "$(stat -c '%U:%G:%a' -- "$unit_snapshot")" = 'root:root:644' ] || {
        echo "current release systemd snapshot is missing or unsafe: $unit" >&2
        exit 66
      }
    done
    if [ "$freshness_service_exists" != 'true' ]; then
      for unit in $freshness_systemd_units; do
        [ ! -e "$current_unit_store/$unit" ] && [ ! -L "$current_unit_store/$unit" ] || {
          echo "legacy current release has an unexpected freshness unit snapshot: $unit" >&2
          exit 66
        }
      done
    fi
  else
    install -d -o root -g root -m 0700 "$current_unit_store"
    for unit in $installed_systemd_units; do
      install -o root -g root -m 0644 "/etc/systemd/system/$unit" \
        "$current_unit_store/$unit"
    done
  fi
  install -d -o root -g root -m 0700 "$candidate_unit_store"
validate_committed_marker() {
  committed_store="$1"
  committed_release="$2"
  committed_marker="$committed_store/COMMITTED"
  [ -f "$committed_marker" ] && [ ! -L "$committed_marker" ] && \
    [ "$(readlink -f -- "$committed_marker")" = "$committed_marker" ] && \
    [ "$(stat -c '%U:%G:%a' -- "$committed_marker")" = 'root:root:400' ] || \
    return 1
  committed_value=''
  IFS= read -r committed_value < "$committed_marker" || true
  [ "$committed_value" = "$committed_release" ]
}
write_committed_marker() {
  committed_store="$1"
  committed_release="$2"
  committed_marker="$committed_store/COMMITTED"
  if [ -e "$committed_marker" ] || [ -L "$committed_marker" ]; then
    validate_committed_marker "$committed_store" "$committed_release"
    return
  fi
  committed_tmp="$(mktemp "$committed_store/.COMMITTED.XXXXXX")" || return 1
  if ! printf '%s\n' "$committed_release" > "$committed_tmp" || \
     ! chown root:root -- "$committed_tmp" || \
     ! chmod 0400 -- "$committed_tmp" || \
     ! mv -Tf "$committed_tmp" "$committed_marker"; then
    rm -f -- "$committed_tmp"
    return 1
  fi
  validate_committed_marker "$committed_store" "$committed_release"
}
reject_release_symlinks() {
  checked_release="$1"
  symlink_path="$(find "$checked_release" -type l -print -quit)"
  [ -z "$symlink_path" ] || {
    echo "release contains a symbolic link: $symlink_path" >&2
    return 1
  }
}
remove_node_modules_tree() {
  release_root="$1"
  node_modules="$release_root/web/node_modules"
  [ -d "$node_modules" ] && [ ! -L "$node_modules" ] && \
    [ "$(readlink -f -- "$node_modules")" = "$node_modules" ] || {
    echo "web dependency tree is missing or unsafe" >&2
    return 1
  }
  find "$node_modules" -depth -delete
  [ ! -e "$node_modules" ] && [ ! -L "$node_modules" ]
}
write_release_manifest() {
  manifest_store="$1"
  manifest_release="$2"
  manifest_path="$manifest_store/RELEASE.MANIFEST.json"
  reject_release_symlinks "$manifest_release" || return 1
  if [ -e "$manifest_path" ] || [ -L "$manifest_path" ]; then
    [ -f "$manifest_path" ] && [ ! -L "$manifest_path" ] && \
      [ "$(stat -c '%U:%G:%a' -- "$manifest_path")" = 'root:root:400' ] && \
      python3 "$manifest_tool" verify "$manifest_release" "$manifest_path"
    return
  fi
  manifest_tmp="$(mktemp "$manifest_store/.RELEASE.MANIFEST.XXXXXX")" || return 1
  if ! python3 "$manifest_tool" write "$manifest_release" "$manifest_tmp" || \
     ! chown root:root -- "$manifest_tmp" || \
     ! chmod 0400 -- "$manifest_tmp" || \
     ! mv -Tf "$manifest_tmp" "$manifest_path"; then
    rm -f -- "$manifest_tmp"
    return 1
  fi
  python3 "$manifest_tool" verify "$manifest_release" "$manifest_path"
}
verify_release_database() {
  verified_release="$1"
  su -s /bin/sh guardian -c \
    "cd '$verified_release' && '$verified_release/.venv/bin/alembic' -c controller/alembic.ini current --check-heads" && \
  su -s /bin/sh guardian -c \
    "cd '$verified_release' && '$verified_release/.venv/bin/python' -c 'from sqlalchemy import select; from guardian.database import SessionLocal; from guardian.models import Agent, Approval, AuditLog, Host, Incident, RecoveryPoint; db = SessionLocal(); [db.execute(select(model.id).limit(1)).all() for model in (Host, Agent, Incident, Approval, AuditLog, RecoveryPoint)]; db.close()'"
}
verify_running_release() {
  verified_release="$1"
  curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    http://127.0.0.1:8090/health >/dev/null && \
  verify_release_database "$verified_release"
}
verify_candidate_release() {
  curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    http://127.0.0.1:8090/health >/dev/null && \
  curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    http://127.0.0.1:8090/ready >/dev/null && \
  verify_release_database "$release_dir"
}
restore_previous_application() {
  run_lifecycle_recovery
}
timer_was_active='false'
restart_backup_timer() {
  exit_status=$?
  trap - EXIT
  if [ -e "$journal_file" ] || [ -L "$journal_file" ]; then
    if ! run_lifecycle_recovery; then
      echo "previous controller could not be restored during lifecycle cleanup" >&2
      exit_status=72
    fi
  fi
  exit "$exit_status"
}
trap restart_backup_timer EXIT
trap 'exit 75' HUP INT TERM
printf '%s\n' "$current" > "$backup_dir/PREVIOUS_RELEASE"
cp -a /etc/vps-guardian "$backup_dir/config"
find "$backup_dir/config" -type f -exec sha256sum {} \; > "$backup_dir/SHA256SUMS"

install -d -o root -g root -m 0700 "$release_dir"
install -d -o guardian-backup -g guardian-backup -m 0750 \
  /var/lib/vps-guardian-backup /var/lib/vps-guardian-backup/restic \
  /var/cache/vps-guardian-backup
release_archive="$release_dir/.reviewed-source.tar"
git -C "$source_dir" archive --format=tar --output="$release_archive" \
  "$source_commit" -- controller deploy/systemd runbooks scripts web \
  README.md pyproject.toml requirements-build.lock requirements.lock
(cd "$release_dir" && umask 022 && \
  tar --no-same-owner --no-same-permissions -xf "$release_archive")
rm -f -- "$release_archive"
printf '%s\n' "$source_commit" > "$release_dir/SOURCE_COMMIT"
reject_release_symlinks "$release_dir" || exit 66
[ -d "$release_dir/deploy/systemd" ] && [ ! -L "$release_dir/deploy" ] && \
  [ ! -L "$release_dir/deploy/systemd" ] || {
  echo "candidate systemd directory is missing or unsafe" >&2
  exit 66
}
for unit in $managed_systemd_units; do
  unit_source="$release_dir/deploy/systemd/$unit"
  [ -f "$unit_source" ] && [ ! -L "$unit_source" ] || {
    echo "candidate release is missing a regular systemd unit: $unit" >&2
    exit 66
  }
  install -o root -g root -m 0644 "$unit_source" "$candidate_unit_store/$unit"
done
current_is_committed='false'
if [ -e "$current_unit_store/COMMITTED" ] || [ -L "$current_unit_store/COMMITTED" ]; then
  validate_committed_marker "$current_unit_store" "$current" || {
    echo "current release COMMITTED marker is unsafe or mismatched" >&2
    exit 66
  }
  current_is_committed='true'
fi
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
remove_node_modules_tree "$release_dir"
reject_release_symlinks "$release_dir" || exit 66
chown -hR root:guardian-release "$release_dir"
find "$release_dir" -type d -exec chmod 0550 {} \;
find "$release_dir" -type f -perm /111 -exec chmod 0550 {} \;
find "$release_dir" -type f ! -perm /111 -exec chmod 0440 {} \;
write_release_manifest "$candidate_unit_store" "$release_dir" || {
  echo "candidate checksum manifest could not be created or verified" >&2
  exit 72
}
timer_initial_state="$(service_state vps-guardian-backup.timer)"
if [ "$freshness_service_exists" = 'true' ]; then
  freshness_timer_initial_state="$(service_state vps-guardian-backup-freshness.timer)"
  [ "$freshness_timer_initial_state" = "$timer_initial_state" ] || {
    echo 'backup and freshness timers must have the same lifecycle state' >&2
    exit 72
  }
fi
if [ "$timer_initial_state" = 'active' ]; then
  timer_was_active='true'
fi
for service in vps-guardian-backup.service vps-guardian-backup-freshness.service; do
  if systemctl is-active --quiet "$service"; then
    echo "a backup scheduling operation is already running; retry after it completes" >&2
    exit 75
  fi
done
unset GUARDIAN_DATABASE_URL
set -a
. "$controller_env"
set +a
export GUARDIAN_DATABASE_URL_FILE="$controller_database_url"
export GUARDIAN_CONTROLLER_SIGNING_KEY_FILE="$controller_signing_key"
database_revision() {
  revision_release="$1"
  su -s /bin/sh guardian -c \
    "cd '$revision_release' && '$revision_release/.venv/bin/python' -c 'from alembic.migration import MigrationContext; from guardian.database import engine; connection = engine.connect(); heads = MigrationContext.configure(connection).get_current_heads(); print(\"+\".join(heads) if heads else \"base\"); connection.close()'"
}
db_revision_before="$(database_revision "$current")"
if [ "$freshness_service_exists" = 'true' ]; then
  lifecycle_journal init --operation upgrade --previous-release "$current" \
    --candidate-release "$release_dir" --db-revision-before "$db_revision_before" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-controller.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup.timer" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup-freshness.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup-freshness.timer" \
    --timer-state "$timer_initial_state" --controller-state active >/dev/null
else
  lifecycle_journal init --operation upgrade --previous-release "$current" \
    --candidate-release "$release_dir" --db-revision-before "$db_revision_before" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-controller.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup.service" \
    --unit-metadata-ref "$unit_backup_dir/vps-guardian-backup.timer" \
    --timer-state "$timer_initial_state" --controller-state active >/dev/null
fi
if [ "$timer_initial_state" = 'active' ]; then
  systemctl stop vps-guardian-backup.timer
  if [ "$freshness_service_exists" = 'true' ]; then
    systemctl stop vps-guardian-backup-freshness.timer
  fi
fi
lifecycle_journal update --phase prepared >/dev/null
if [ "$current_is_committed" != 'true' ]; then
  if ! install -o root -g root -m 0644 \
      "$candidate_unit_store/vps-guardian-controller.service" \
      /etc/systemd/system/vps-guardian-controller.service || \
     ! systemctl daemon-reload || \
     ! systemctl restart vps-guardian-controller.service || \
     ! verify_running_release "$current"; then
    if restore_previous_application; then
      echo "legacy controller unit hardening failed; previous unit was restored" >&2
      exit 71
    fi
    echo "legacy controller unit hardening and restoration both failed" >&2
    exit 72
  fi
  install -o root -g root -m 0644 \
    "$candidate_unit_store/vps-guardian-controller.service" \
    "$current_unit_store/vps-guardian-controller.service"
fi
verify_running_release "$current" || {
  echo "current controller database/Alembic readiness check failed" >&2
  exit 72
}
if [ "$current_is_committed" = 'true' ]; then
  write_release_manifest "$current_unit_store" "$current" || {
    echo "current release checksum manifest could not be verified" >&2
    exit 72
  }
else
  echo "legacy current release is available only for this upgrade transaction; it remains ineligible for later rollback" >&2
fi
su -s /bin/sh guardian-backup -c \
  "sh '$release_dir/scripts/run-backup-command.sh' guardian-backup controller --host controller --service controller --source '$current/runbooks'" \
  > "$backup_dir/recovery-point.json"
systemctl is-active --quiet vps-guardian-controller.service || {
  echo "current controller must be active before the migration outage" >&2
  exit 72
}
if ! systemctl stop vps-guardian-controller.service; then
  restore_previous_application || true
  echo "current controller could not be quiesced for schema migration" >&2
  exit 72
fi
lifecycle_journal update --phase quiesced --controller-state inactive >/dev/null
if ! su -s /bin/sh guardian -c \
  "cd '$release_dir' && '$release_dir/.venv/bin/alembic' -c controller/alembic.ini upgrade head"; then
  restore_previous_application || true
  echo "candidate schema migration failed; inspect or restore the pre-upgrade recovery point" >&2
  exit 72
fi
db_revision_after="$(database_revision "$release_dir")"
lifecycle_journal update --phase database_updated \
  --db-revision-after "$db_revision_after" >/dev/null
for unit in $managed_systemd_units; do
  if ! install -o root -g root -m 0644 "$candidate_unit_store/$unit" \
    "/etc/systemd/system/$unit"; then
    restore_previous_application || true
    echo "candidate unit deployment failed after schema migration; manual recovery is required" >&2
    exit 72
  fi
done
if ! systemctl daemon-reload; then
  restore_previous_application || true
  echo "candidate unit reload failed after schema migration; manual recovery is required" >&2
  exit 72
fi
lifecycle_journal update --phase units_updated >/dev/null
if ! switch_current "$release_dir"; then
  restore_previous_application || true
  echo "candidate activation failed after schema migration; manual recovery is required" >&2
  exit 72
fi
lifecycle_journal update --phase candidate_activated >/dev/null
if ! systemctl restart vps-guardian-controller.service || \
   ! verify_candidate_release; then
  restore_previous_application || true
  echo "candidate readiness failed after schema migration; manual recovery is required" >&2
  exit 72
fi
lifecycle_journal update --phase verified --controller-state active >/dev/null
if [ "$timer_was_active" = 'true' ] && \
   { ! systemctl enable --now vps-guardian-backup.timer \
       vps-guardian-backup-freshness.timer || \
     ! systemctl is-active --quiet vps-guardian-backup.timer || \
     ! systemctl is-active --quiet vps-guardian-backup-freshness.timer; }; then
  restore_previous_application || true
  echo "candidate timer failed after schema migration; manual recovery is required" >&2
  exit 72
fi
write_release_manifest "$candidate_unit_store" "$release_dir" || {
  restore_previous_application || true
  echo "candidate checksum manifest failed after schema migration; manual recovery is required" >&2
  exit 72
}
write_committed_marker "$candidate_unit_store" "$release_dir" || {
  restore_previous_application || true
  echo "candidate commit marker failed after schema migration; manual recovery is required" >&2
  exit 72
}
timer_was_active='false'
lifecycle_journal update --phase committed --controller-state active \
  --timer-state "$timer_initial_state" >/dev/null
lifecycle_journal clear
printf 'upgraded to %s; approval %s; backup %s\n' "$release_id" "$approval_id" "$backup_dir"
