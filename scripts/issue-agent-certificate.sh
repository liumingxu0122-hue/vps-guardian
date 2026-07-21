#!/bin/sh
set -eu

if [ "$#" -lt 3 ]; then
  echo "usage: $0 PKI_DIR AGENT_NAME OUTPUT_DIR [DAYS]" >&2
  exit 64
fi
pki_dir="$1"
agent_name="$2"
output_dir="$3"
days="${4:-90}"

case "$agent_name" in
  *[!A-Za-z0-9_.-]*|'') echo "invalid Agent name" >&2; exit 64 ;;
esac
case "$days" in
  *[!0-9]*|'') echo "invalid certificate lifetime" >&2; exit 64 ;;
esac
if [ "$days" -lt 1 ] || [ "$days" -gt 397 ]; then
  echo "certificate lifetime must be between 1 and 397 days" >&2
  exit 64
fi
if [ ! -r "$pki_dir/private/agent-ca.key" ] || [ ! -r "$pki_dir/agent-ca.crt" ]; then
  echo "Agent CA is incomplete" >&2
  exit 66
fi
command -v flock >/dev/null 2>&1 || { echo "missing command: flock" >&2; exit 69; }
umask 077
lock_file="$pki_dir/.pki.lock"
: > "$lock_file"
chmod 0600 "$lock_file"
exec 9>"$lock_file"
flock -x 9
if [ -e "$output_dir/agent.key" ] || [ -e "$output_dir/agent.crt" ]; then
  echo "refusing to overwrite an existing Agent identity" >&2
  exit 73
fi

mkdir -p "$output_dir"
chmod 0700 "$output_dir"
openssl genpkey -algorithm ED25519 -out "$output_dir/agent.key"
openssl req -new -key "$output_dir/agent.key" -subj "/CN=$agent_name" -out "$output_dir/agent.csr"
openssl ca -batch -config "$pki_dir/openssl.cnf" -extensions client_cert -days "$days" \
  -in "$output_dir/agent.csr" -out "$output_dir/agent.crt"
cp "$pki_dir/agent-ca.crt" "$output_dir/agent-ca.crt"
openssl genpkey -algorithm ED25519 -out "$output_dir/signing-ed25519.pem"
rm -f "$output_dir/agent.csr"
chmod 0600 "$output_dir/agent.key" "$output_dir/signing-ed25519.pem"
chmod 0644 "$output_dir/agent.crt" "$output_dir/agent-ca.crt"
openssl verify -CAfile "$output_dir/agent-ca.crt" "$output_dir/agent.crt"
openssl x509 -in "$output_dir/agent.crt" -noout -serial -enddate -fingerprint -sha256
