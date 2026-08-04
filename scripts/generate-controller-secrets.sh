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

script_dir="$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)"
sh "$script_dir/pki-init.sh" "$target/pki"
chmod 0600 "$target/pki/agent-ca.crt" "$target/pki/private/agent-ca.key"

mkdir -p "$target/enrollment-https-pki/private"
chmod 0700 "$target/enrollment-https-pki" "$target/enrollment-https-pki/private"
openssl genpkey -algorithm ED25519 \
  -out "$target/enrollment-https-pki/private/enrollment-https-ca.key"
openssl req -new -x509 \
  -key "$target/enrollment-https-pki/private/enrollment-https-ca.key" \
  -days 3650 \
  -subj "/CN=VPS Guardian Enrollment HTTPS CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$target/enrollment-https-pki/enrollment-https-ca-bundle.pem"
openssl genpkey -algorithm ED25519 -out "$target/server.key"
openssl req -new -key "$target/server.key" -subj "/CN=$gateway_name" \
  -addext "subjectAltName=DNS:$gateway_name" -out "$target/server.csr"
cat > "$target/enrollment-https-pki/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$gateway_name
EOF
openssl x509 -req -in "$target/server.csr" \
  -CA "$target/enrollment-https-pki/enrollment-https-ca-bundle.pem" \
  -CAkey "$target/enrollment-https-pki/private/enrollment-https-ca.key" \
  -CAcreateserial -days 90 -extfile "$target/enrollment-https-pki/server.ext" \
  -out "$target/server.crt"
rm -f "$target/server.csr" "$target/enrollment-https-pki/server.ext" \
  "$target/enrollment-https-pki/enrollment-https-ca-bundle.srl"
chmod 0600 "$target/enrollment-https-pki/private/enrollment-https-ca.key" \
  "$target/enrollment-https-pki/enrollment-https-ca-bundle.pem"
openssl verify -purpose sslserver -verify_hostname "$gateway_name" \
  -CAfile "$target/enrollment-https-pki/enrollment-https-ca-bundle.pem" \
  "$target/server.crt"
openssl x509 -in "$target/server.crt" -noout -checkhost "$gateway_name" >/dev/null
mkdir -p "$target/gateway-pki"
chmod 0755 "$target/gateway-pki"
install -m 0644 "$target/pki/agent-ca.crt" "$target/gateway-pki/agent-ca.crt"
install -m 0644 "$target/pki/agent-ca.crl" "$target/gateway-pki/agent-ca.crl"
checksum_file="$(mktemp)"
trap 'rm -f -- "$checksum_file"' EXIT HUP INT TERM
(cd "$target" && find . -type f ! -name SHA256SUMS \
  -exec sha256sum {} \; | sort) > "$checksum_file"
mv "$checksum_file" "$target/SHA256SUMS"
trap - EXIT HUP INT TERM
chmod 0600 "$target/SHA256SUMS"
printf 'created controller secrets in %s; store protected off-host copies of the CA, Restic password, and field key\n' "$target"
