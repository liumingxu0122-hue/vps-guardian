#!/bin/sh
set -eu

target="${1:-./secrets}"
gateway_name="${2:-}"
case "$gateway_name" in
  ''|*[!A-Za-z0-9.-]*)
    echo "usage: $0 [SECRETS_DIRECTORY] AGENT_GATEWAY_DNS_NAME" >&2
    exit 64
    ;;
esac
if [ -e "$target" ] && [ "$(find "$target" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  echo "refusing to add secrets to a non-empty directory" >&2
  exit 73
fi
umask 077
mkdir -p "$target"
chmod 0700 "$target"

postgres_password="$(openssl rand -hex 32)"
printf '%s\n' "$postgres_password" > "$target/postgres-password"
printf 'postgresql+psycopg://guardian:%s@database:5432/guardian\n' "$postgres_password" > "$target/database-url"
unset postgres_password
openssl rand -hex 48 > "$target/jwt-secret"
openssl rand -base64 32 | tr '+/' '-_' > "$target/field-encryption-key"
openssl rand -hex 32 > "$target/enrollment-token"
openssl rand -hex 48 > "$target/proxy-auth"
openssl rand -base64 48 > "$target/restic-password"
openssl genpkey -algorithm ED25519 -out "$target/controller-ed25519.pem"
chmod 0600 "$target"/*

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
sh "$script_dir/pki-init.sh" "$target/pki"
openssl genpkey -algorithm ED25519 -out "$target/server.key"
openssl req -new -key "$target/server.key" -subj "/CN=$gateway_name" \
  -addext "subjectAltName=DNS:$gateway_name" -out "$target/server.csr"
openssl ca -batch -config "$target/pki/openssl.cnf" -extensions server_cert -days 90 \
  -in "$target/server.csr" -out "$target/server.crt"
rm -f "$target/server.csr"
openssl verify -CAfile "$target/pki/agent-ca.crt" "$target/server.crt"
openssl x509 -in "$target/server.crt" -noout -checkhost "$gateway_name" >/dev/null
mkdir -p "$target/gateway-pki"
chmod 0755 "$target/gateway-pki"
install -m 0644 "$target/pki/agent-ca.crt" "$target/gateway-pki/agent-ca.crt"
install -m 0644 "$target/pki/agent-ca.crl" "$target/gateway-pki/agent-ca.crl"
(cd "$target" && find . -type f ! -name SHA256SUMS -exec sha256sum {} \; | sort > SHA256SUMS)
chmod 0600 "$target/SHA256SUMS"
printf 'created controller secrets in %s; store protected off-host copies of the CA, Restic password, and field key\n' "$target"
