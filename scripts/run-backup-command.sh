#!/bin/sh
set -eu

if [ "$(id -un)" != 'guardian-backup' ]; then
  echo "backup commands must run as the guardian-backup service account" >&2
  exit 77
fi

tool="${1:-}"
case "$tool" in
  guardian-backup|guardian-recovery) shift ;;
  *) echo "usage: $0 guardian-backup|guardian-recovery [ARGUMENT ...]" >&2; exit 64 ;;
esac

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
release_dir="$(CDPATH= cd -- "$script_dir/.." && pwd)"
executable="$release_dir/.venv/bin/$tool"
[ -x "$executable" ] || {
  echo "backup command is not installed in this release: $tool" >&2
  exit 69
}

repository_file='/etc/vps-guardian-backup-secrets/restic-repository'
database_url_file='/etc/vps-guardian/database-url'
[ -d /etc/vps-guardian ] && [ ! -L /etc/vps-guardian ] && \
  [ "$(readlink -f -- /etc/vps-guardian)" = '/etc/vps-guardian' ] && \
  [ "$(stat -c '%U:%G:%a' -- /etc/vps-guardian)" = \
    'root:guardian-database:750' ] || {
  echo "/etc/vps-guardian must be root:guardian-database with mode 0750" >&2
  exit 77
}
[ -f "$database_url_file" ] && [ ! -L "$database_url_file" ] && \
  [ "$(readlink -f -- "$database_url_file")" = "$database_url_file" ] && \
  [ -s "$database_url_file" ] && \
  [ "$(stat -c '%U:%G:%a' -- "$database_url_file")" = \
    'root:guardian-database:640' ] || {
  echo "$database_url_file must be root:guardian-database with mode 0640" >&2
  exit 77
}
repository="$(python3 - "$repository_file" <<'PY'
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
)" || { echo "Restic repository file contains an invalid value" >&2; exit 77; }
case "$repository" in
  s3:*) ;;
  /*)
    canonical_repository="$(readlink -m -- "$repository")" || exit 77
    [ "$canonical_repository" = "$repository" ] && \
    { [ "$repository" = '/var/lib/vps-guardian-backup/restic' ] || \
        case "$repository" in /var/lib/vps-guardian-backup/restic/*) true ;; *) false ;; esac; } || {
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
unset repository

unset RESTIC_REPOSITORY RESTIC_PASSWORD AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN AWS_DEFAULT_REGION
export GUARDIAN_DATABASE_URL_FILE="$database_url_file"
export GUARDIAN_SOURCE_COMMIT_FILE="$release_dir/SOURCE_COMMIT"
export RESTIC_REPOSITORY_FILE="$repository_file"
export RESTIC_PASSWORD_FILE='/etc/vps-guardian-backup-secrets/restic-password'
export AWS_ACCESS_KEY_ID_FILE='/etc/vps-guardian-backup-secrets/aws-access-key-id'
export AWS_SECRET_ACCESS_KEY_FILE='/etc/vps-guardian-backup-secrets/aws-secret-access-key'
export AWS_DEFAULT_REGION_FILE='/etc/vps-guardian-backup-secrets/aws-region'
export GUARDIAN_CONTROLLED_BACKUP_CONFIG='1'
export RESTIC_LOCAL_REPOSITORY_ROOT='/var/lib/vps-guardian-backup/restic'
export RESTIC_CACHE_DIR='/var/cache/vps-guardian-backup'

exec "$executable" "$@"
