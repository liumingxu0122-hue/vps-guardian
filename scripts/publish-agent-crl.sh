#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 COMPOSE_DIRECTORY GATEWAY_PKI_DIRECTORY SERIAL_FILE" >&2
  exit 64
fi
compose_directory="$1"
pki_directory="$2"
serial_file="$3"

for directory in "$compose_directory" "$pki_directory"; do
  [ "${directory#/}" != "$directory" ] && [ -d "$directory" ] && [ ! -L "$directory" ] || {
    echo "directories must be absolute, existing, and not symbolic links" >&2
    exit 64
  }
done
[ "${serial_file#/}" != "$serial_file" ] && [ -f "$serial_file" ] && [ ! -L "$serial_file" ] || {
  echo "serial file must be an absolute regular file" >&2
  exit 64
}
for command in docker openssl sha256sum awk cp mv rm sed sleep tr; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 69; }
done

active="$pki_directory/agent-ca.crl"
[ -f "$active" ] && [ ! -L "$active" ] || { echo "active Agent CRL is unsafe" >&2; exit 66; }
candidate_name="agent-ca.crl.candidate.$$"
candidate="$pki_directory/$candidate_name"
previous="$pki_directory/agent-ca.crl.previous.$$"
cleanup() { rm -f "$candidate"; }
trap cleanup EXIT HUP INT TERM

cd "$compose_directory"
docker compose run --rm --no-deps --user 0:0 \
  --entrypoint controller-entrypoint \
  -v "$pki_directory:/work/gateway-pki" \
  -v "$serial_file:/work/revoked-serial:ro" \
  controller guardian-admin build-agent-crl \
  --current-crl /work/gateway-pki/agent-ca.crl \
  --serial-file /work/revoked-serial \
  --output "/work/gateway-pki/$candidate_name" \
  --execute --confirm 'BUILD VPS GUARDIAN AGENT CRL'

docker compose exec -T agent-gateway \
  /usr/local/bin/guardian-agent-gateway-entrypoint \
  --validate-crl "/etc/vps-guardian/gateway-pki/$candidate_name"
openssl crl -in "$candidate" -noout -verify -CAfile "$pki_directory/agent-ca.crt" >/dev/null
crl_number="$(openssl crl -in "$candidate" -noout -crlnumber | awk -F= '{print $2}')"
case "$crl_number" in 0x*) crl_number="$((crl_number))" ;; esac
checksum="$(sha256sum "$candidate" | awk '{print $1}')"
certificate_serial="$(tr -d '[:space:]' < "$serial_file" | tr 'a-f' 'A-F')"
case "$certificate_serial" in
  ''|*[!A-F0-9]*) echo "certificate serial file is invalid" >&2; exit 65 ;;
esac
certificate_serial="$(printf '%s' "$certificate_serial" | sed 's/^0*//')"
[ -n "$certificate_serial" ] || certificate_serial=0

cp -p "$active" "$previous"
chmod 0644 "$candidate"
mv -f "$candidate" "$active"
if ! docker compose up -d --no-deps --force-recreate agent-gateway; then
  mv -f "$previous" "$active"
  docker compose up -d --no-deps --force-recreate agent-gateway >/dev/null
  echo "Agent Gateway recreation failed; previous CRL restored" >&2
  exit 1
fi

healthy=false
attempt=0
while [ "$attempt" -lt 30 ]; do
  status="$(docker compose ps --format json agent-gateway | awk 'NR==1 {print}')"
  case "$status" in *'"Health":"healthy"'*) healthy=true; break ;; esac
  attempt=$((attempt + 1))
  sleep 2
done
if [ "$healthy" != true ]; then
  mv -f "$previous" "$active"
  docker compose up -d --no-deps --force-recreate agent-gateway >/dev/null
  echo "Agent Gateway did not become healthy; previous CRL restored" >&2
  exit 1
fi
rm -f "$previous"
docker compose exec -T controller controller-entrypoint guardian-admin record-crl-publication \
  --crl-number "$crl_number" --sha256 "$checksum" \
  --certificate-serial "$certificate_serial" --outcome success \
  --reason-code agent_identity_revoked --execute \
  --confirm 'RECORD VPS GUARDIAN CRL PUBLICATION'
trap - EXIT HUP INT TERM
echo "Agent CRL published and Agent Gateway is healthy"
