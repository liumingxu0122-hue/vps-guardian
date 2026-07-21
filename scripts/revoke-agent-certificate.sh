#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 PKI_DIR AGENT_CERTIFICATE" >&2
  exit 64
fi
pki_dir="$1"
certificate="$2"
command -v flock >/dev/null 2>&1 || { echo "missing command: flock" >&2; exit 69; }
umask 077
lock_file="$pki_dir/.pki.lock"
: > "$lock_file"
chmod 0600 "$lock_file"
exec 9>"$lock_file"
flock -x 9
openssl verify -CAfile "$pki_dir/agent-ca.crt" "$certificate"
openssl ca -batch -config "$pki_dir/openssl.cnf" -revoke "$certificate" -crl_reason cessationOfOperation
temporary="$pki_dir/agent-ca.crl.tmp"
openssl ca -batch -config "$pki_dir/openssl.cnf" -gencrl -out "$temporary"
chmod 0644 "$temporary"
mv "$temporary" "$pki_dir/agent-ca.crl"
openssl crl -in "$pki_dir/agent-ca.crl" -noout -lastupdate -nextupdate
