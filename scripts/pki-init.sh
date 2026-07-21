#!/bin/sh
set -eu

target="${1:-/etc/vps-guardian/pki}"
if [ -e "$target/agent-ca.key" ] || [ -e "$target/agent-ca.crt" ]; then
  echo "refusing to overwrite an existing Agent CA" >&2
  exit 73
fi

umask 077
mkdir -p "$target" "$target/newcerts" "$target/private"
chmod 0700 "$target" "$target/newcerts" "$target/private"
: > "$target/index.txt"
printf '1000\n' > "$target/serial"
printf '1000\n' > "$target/crlnumber"

cat > "$target/openssl.cnf" <<EOF
[ ca ]
default_ca = guardian_ca

[ guardian_ca ]
dir = $target
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = \$dir/agent-ca.crt
private_key = \$dir/private/agent-ca.key
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_days = 90
default_crl_days = 7
default_md = sha256
crl_extensions = guardian_crl
policy = guardian_policy
unique_subject = no
copy_extensions = copy

[ guardian_policy ]
commonName = supplied

[ client_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ server_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ guardian_ca_certificate ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ guardian_crl ]
authorityKeyIdentifier = keyid:always
EOF

openssl genpkey -algorithm ED25519 -out "$target/private/agent-ca.key"
openssl req -new -x509 -key "$target/private/agent-ca.key" -days 3650 \
  -subj '/CN=VPS Guardian Agent CA' \
  -addext 'basicConstraints=critical,CA:true' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -addext 'authorityKeyIdentifier=keyid:always,issuer' \
  -out "$target/agent-ca.crt"
openssl ca -config "$target/openssl.cnf" -gencrl -out "$target/agent-ca.crl" -batch
chmod 0600 "$target/private/agent-ca.key"
chmod 0644 "$target/agent-ca.crt" "$target/agent-ca.crl" "$target/openssl.cnf"
openssl x509 -in "$target/agent-ca.crt" -noout -fingerprint -sha256
