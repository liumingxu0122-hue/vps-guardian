#!/usr/bin/env bash

# Read a root-owned secret file into a caller-provided variable without
# depending on a trailing newline. The value is never written to stdout.
read_root_secret_file() {
  if (( $# != 2 )); then
    echo "read_root_secret_file requires a file and output variable" >&2
    return 2
  fi

  local secret_file="$1"
  local output_variable="$2"
  local owner_uid
  local owner_mode
  local secret_value
  local identity_before
  local identity_after

  if [[ ! "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "Secret output variable is invalid" >&2
    return 2
  fi
  if [[ ! -e "$secret_file" ]]; then
    echo "Secret file is missing" >&2
    return 1
  fi
  if [[ -L "$secret_file" ]]; then
    echo "Secret file must not be a symbolic link" >&2
    return 1
  fi
  if [[ ! -f "$secret_file" ]]; then
    echo "Secret path must be a regular file" >&2
    return 1
  fi

  owner_uid="$(stat -c '%u' -- "$secret_file")"
  owner_mode="$(stat -c '%a' -- "$secret_file")"
  if [[ "$owner_uid" != "0" ]]; then
    echo "Secret file must be owned by root" >&2
    return 1
  fi
  if (( (8#$owner_mode & 8#077) != 0 )); then
    echo "Secret file permissions are too broad" >&2
    return 1
  fi
  if [[ ! -s "$secret_file" ]]; then
    echo "Secret file is empty" >&2
    return 1
  fi
  identity_before="$(stat -Lc '%d:%i:%u:%a:%s' -- "$secret_file")"
  if od -An -v -t x1 -- "$secret_file" |
    grep -Eq '(^|[[:space:]])00([[:space:]]|$)'; then
    echo "Secret file contains a NUL byte" >&2
    return 1
  fi

  secret_value="$(<"$secret_file")"
  identity_after="$(stat -Lc '%d:%i:%u:%a:%s' -- "$secret_file")"
  if [[ "$identity_after" != "$identity_before" ]]; then
    unset secret_value
    echo "Secret file changed while it was being read" >&2
    return 1
  fi
  if [[ -z "$secret_value" ]]; then
    echo "Secret file is empty after newline normalization" >&2
    return 1
  fi
  printf -v "$output_variable" '%s' "$secret_value"
  unset secret_value
}
