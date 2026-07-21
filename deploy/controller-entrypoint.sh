#!/bin/sh
set -eu

read_secret() {
  variable="$1"
  file="$2"
  if [ ! -r "$file" ]; then
    echo "required secret file is not readable: $file" >&2
    exit 78
  fi
  value="$(cat "$file")"
  if [ -z "$value" ]; then
    echo "required secret file is empty: $file" >&2
    exit 78
  fi
  export "$variable=$value"
}

database_url_file="${GUARDIAN_DATABASE_URL_FILE:-/run/secrets/database_url}"
[ -f "$database_url_file" ] && [ ! -L "$database_url_file" ] && \
  [ -r "$database_url_file" ] && [ -s "$database_url_file" ] || {
  echo "required database URL file is missing or unsafe" >&2
  exit 78
}
unset GUARDIAN_DATABASE_URL
export GUARDIAN_DATABASE_URL_FILE="$database_url_file"
read_secret GUARDIAN_JWT_SECRET "${GUARDIAN_JWT_SECRET_FILE:-/run/secrets/jwt_secret}"
read_secret GUARDIAN_FIELD_ENCRYPTION_KEY "${GUARDIAN_FIELD_ENCRYPTION_KEY_FILE:-/run/secrets/field_encryption_key}"
read_secret GUARDIAN_AGENT_ENROLLMENT_TOKEN "${GUARDIAN_AGENT_ENROLLMENT_TOKEN_FILE:-/run/secrets/enrollment_token}"
read_secret GUARDIAN_TRUSTED_PROXY_CERT_HEADER_SECRET "${GUARDIAN_PROXY_AUTH_FILE:-/run/secrets/proxy_auth}"

exec "$@"
