#!/bin/sh
set -eu

config_template='/etc/vps-guardian/agent-gateway.haproxy.cfg'
runtime_config='/tmp/guardian-agent-gateway.cfg'
runtime_certificate='/tmp/agent-gateway.pem'
secret_file="${GUARDIAN_PROXY_AUTH_FILE:-/run/secrets/proxy_auth}"
certificate_file='/run/secrets/agent_gateway_certificate'
private_key_file='/run/secrets/agent_gateway_private_key'

healthcheck() {
  wget --quiet --output-document=/dev/null --timeout=3 http://127.0.0.1:8080/health
}

render_config() {
  [ -r "$secret_file" ] || { echo 'gateway authentication Secret is not readable' >&2; exit 78; }
  secret="$(cat "$secret_file")"
  [ "${#secret}" -ge 32 ] || { echo 'gateway authentication Secret is too short' >&2; exit 78; }
  case "$secret" in
    *[!A-Za-z0-9_.-]*) echo 'gateway authentication Secret has unsafe characters' >&2; exit 78 ;;
  esac
  [ -r "$config_template" ] || { echo 'gateway configuration template is missing' >&2; exit 66; }
  [ -r "$certificate_file" ] || { echo 'gateway TLS certificate is missing' >&2; exit 66; }
  [ -r "$private_key_file" ] || { echo 'gateway TLS private key is missing' >&2; exit 66; }
  umask 077
  cat "$certificate_file" "$private_key_file" > "$runtime_certificate"
  sed "s/__GUARDIAN_PROXY_AUTH__/$secret/g" "$config_template" > "$runtime_config"
  unset secret
}

validate_candidate() {
  candidate="${1:-}"
  case "$candidate" in
    /etc/vps-guardian/gateway-pki/agent-ca.crl.candidate.*) ;;
    *) echo 'candidate CRL path is outside the gateway PKI directory' >&2; exit 78 ;;
  esac
  [ -r "$candidate" ] || { echo 'candidate CRL is not readable' >&2; exit 66; }
  [ -r "$runtime_config" ] || { echo 'running gateway configuration is missing' >&2; exit 66; }
  candidate_config="$(mktemp /tmp/guardian-agent-gateway-candidate.XXXXXX)"
  trap 'rm -f "$candidate_config"' EXIT HUP INT TERM
  sed "s|/etc/vps-guardian/gateway-pki/agent-ca.crl|$candidate|" \
    "$runtime_config" > "$candidate_config"
  haproxy -c -f "$candidate_config"
  rm -f "$candidate_config"
  trap - EXIT HUP INT TERM
}

case "${1:-}" in
  --healthcheck) healthcheck; exit ;;
  --validate-crl) validate_candidate "${2:-}"; exit ;;
esac

render_config
exec "$@"
