#!/bin/sh
set -eu

expected_distribution="${EXPECTED_DISTRIBUTION:?}"
expected_architecture="${EXPECTED_ARCHITECTURE:?}"
. /etc/os-release
case "$expected_distribution:$ID" in
  ubuntu:ubuntu|debian:debian|rocky:rocky|alpine:alpine) ;;
  *) echo "unexpected distribution: $ID" >&2; exit 1 ;;
esac
case "$expected_architecture:$(uname -m)" in
  amd64:x86_64|arm64:aarch64) ;;
  *) echo "unexpected architecture: $(uname -m)" >&2; exit 1 ;;
esac

sh -n scripts/install-agent.sh
sh -n scripts/maintain-agent.sh
sh -n scripts/uninstall-agent.sh
grep -F 'umask 077' scripts/maintain-agent.sh >/dev/null
grep -F 'trap rollback EXIT' scripts/maintain-agent.sh >/dev/null
grep -F 'openssl pkeyutl -verify' scripts/install-agent.sh >/dev/null
grep -F 'rm -rf /var/lib/vps-guardian-agent' scripts/maintain-agent.sh >/dev/null
! grep -E 'iptables|firewall-cmd|setenforce|restart (ssh|komari)' scripts/maintain-agent.sh

temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
printf 'version=v0.4.0-test\nsha256_linux_amd64=%064d\nsha256_linux_arm64=%064d\n' \
  1 2 > "$temporary/manifest"
openssl genpkey -algorithm ED25519 -out "$temporary/private.pem"
openssl pkey -in "$temporary/private.pem" -pubout -out "$temporary/public.pem"
openssl pkeyutl -sign -inkey "$temporary/private.pem" -rawin \
  -in "$temporary/manifest" -out "$temporary/manifest.sig"
openssl pkeyutl -verify -pubin -inkey "$temporary/public.pem" -rawin \
  -in "$temporary/manifest" -sigfile "$temporary/manifest.sig"
openssl genpkey -algorithm ED25519 -out "$temporary/wrong-private.pem"
openssl pkey -in "$temporary/wrong-private.pem" -pubout -out "$temporary/wrong-public.pem"
if openssl pkeyutl -verify -pubin -inkey "$temporary/wrong-public.pem" -rawin \
  -in "$temporary/manifest" -sigfile "$temporary/manifest.sig" >/dev/null 2>&1; then
  echo "wrong release key was accepted" >&2
  exit 1
fi
cp "$temporary/manifest.sig" "$temporary/bad.sig"
printf x | dd of="$temporary/bad.sig" bs=1 seek=0 conv=notrunc 2>/dev/null
if openssl pkeyutl -verify -pubin -inkey "$temporary/public.pem" -rawin \
  -in "$temporary/manifest" -sigfile "$temporary/bad.sig" >/dev/null 2>&1; then
  echo "wrong detached signature was accepted" >&2
  exit 1
fi
test "$(sed -n 's/^version=//p' "$temporary/manifest")" = v0.4.0-test
test "$(sed -n 's/^version=//p' "$temporary/manifest")" != v0.3.0-old
printf 'tampered\n' >> "$temporary/manifest"
if openssl pkeyutl -verify -pubin -inkey "$temporary/public.pem" -rawin \
  -in "$temporary/manifest" -sigfile "$temporary/manifest.sig" >/dev/null 2>&1; then
  echo "tampered manifest was accepted" >&2
  exit 1
fi
printf original > "$temporary/artifact"
artifact_sha="$(sha256sum "$temporary/artifact" | awk '{print $1}')"
printf tampered > "$temporary/artifact"
if printf '%s  %s\n' "$artifact_sha" "$temporary/artifact" | sha256sum --check --status; then
  echo "tampered artifact was accepted" >&2
  exit 1
fi

unrelated="$(mktemp)"
printf untouched > "$unrelated"
before="$(sha256sum "$unrelated")"
if (umask 077; : > /sys/vps-guardian-should-fail) 2>/dev/null; then
  echo "read-only filesystem simulation did not fail closed" >&2
  exit 1
fi
test "$before" = "$(sha256sum "$unrelated")"
rm -f "$unrelated"

signal_directory="$(mktemp -d)"
sh -c 'trap '\''rm -rf -- "$1"; exit 130'\'' INT; kill -INT $$' sh "$signal_directory" || status=$?
[ "${status:-0}" -eq 130 ]
[ ! -e "$signal_directory" ]
