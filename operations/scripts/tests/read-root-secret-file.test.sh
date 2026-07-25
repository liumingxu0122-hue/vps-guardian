#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=operations/scripts/read-root-secret-file.sh
source "$script_root/read-root-secret-file.sh"

if (( EUID != 0 )); then
  echo "This test must run as root to verify file ownership" >&2
  exit 1
fi

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT

expect_success() {
  local name="$1"
  local path="$2"
  local value=""
  if ! read_root_secret_file "$path" value 2>/dev/null; then
    echo "FAIL: $name" >&2
    exit 1
  fi
  if [[ "$value" != 'fixed-regression-secret' ]]; then
    echo "FAIL: $name returned an unexpected value" >&2
    exit 1
  fi
  unset value
  echo "PASS: $name"
}

expect_failure() {
  local name="$1"
  local path="$2"
  local value=""
  if read_root_secret_file "$path" value 2>/dev/null; then
    unset value
    echo "FAIL: $name unexpectedly succeeded" >&2
    exit 1
  fi
  unset value
  echo "PASS: $name"
}

printf '%s\n' 'fixed-regression-secret' > "$test_root/with-newline"
chmod 0600 "$test_root/with-newline"
expect_success "newline-terminated 0600" "$test_root/with-newline"

printf '%s' 'fixed-regression-secret' > "$test_root/without-newline"
chmod 0600 "$test_root/without-newline"
expect_success "non-newline-terminated 0600" "$test_root/without-newline"

: > "$test_root/empty"
chmod 0600 "$test_root/empty"
expect_failure "empty" "$test_root/empty"

printf '%s' 'fixed-regression-secret' > "$test_root/non-root"
chmod 0600 "$test_root/non-root"
chown 65534:65534 "$test_root/non-root"
expect_failure "non-root owner" "$test_root/non-root"

printf '%s' 'fixed-regression-secret' > "$test_root/mode-0644"
chmod 0644 "$test_root/mode-0644"
expect_failure "mode 0644" "$test_root/mode-0644"

printf '%s' 'fixed-regression-secret' > "$test_root/mode-0400"
chmod 0400 "$test_root/mode-0400"
expect_success "mode 0400" "$test_root/mode-0400"

ln -s "$test_root/without-newline" "$test_root/symlink"
expect_failure "symbolic link" "$test_root/symlink"

expect_failure "missing file" "$test_root/missing"

printf 'fixed\0regression-secret' > "$test_root/with-nul"
chmod 0600 "$test_root/with-nul"
expect_failure "NUL byte" "$test_root/with-nul"

mkdir "$test_root/directory"
expect_failure "directory" "$test_root/directory"

if read_root_secret_file "$test_root/without-newline" 'invalid-name' 2>/dev/null; then
  echo "FAIL: invalid output variable unexpectedly succeeded" >&2
  exit 1
fi
echo "PASS: invalid output variable"

if read_root_secret_file "$test_root/without-newline" 2>/dev/null; then
  echo "FAIL: invalid argument count unexpectedly succeeded" >&2
  exit 1
fi
echo "PASS: invalid argument count"
