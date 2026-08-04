#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
work=$(mktemp -d)
project=guardian-secret-contract
cleanup() {
  docker compose --project-directory "$repo_root" -p "$project" -f "$repo_root/docker-compose.yml" \
    down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$work"
}
trap cleanup EXIT
canonical="$work/canonical"
sh "$repo_root/scripts/generate-controller-secrets.sh" "$canonical" agent.contract.invalid >/dev/null
chmod 0600 "$canonical/pki/agent-ca.crt"
sh "$repo_root/scripts/prepare-compose-secrets.sh" --secrets-dir "$canonical" >/dev/null
export GUARDIAN_RUNTIME_SECRETS_DIR="$canonical/runtime"
export GUARDIAN_GATEWAY_PKI_DIR="$canonical/gateway-pki"
export GUARDIAN_DOMAIN=panel.contract.invalid
export GUARDIAN_AGENT_DOMAIN=agent.contract.invalid
export ACME_EMAIL=operator@contract.invalid
export RESTIC_REPOSITORY=test-only
sh "$repo_root/scripts/verify-runtime-secret-mounts.sh" \
  --runtime-dir "$canonical/runtime" >/dev/null

compose=(docker compose --project-directory "$repo_root" -p "$project" -f "$repo_root/docker-compose.yml")
"${compose[@]}" config --quiet
"${compose[@]}" up -d database
"${compose[@]}" run --rm controller alembic -c controller/alembic.ini upgrade head
"${compose[@]}" up -d controller agent-gateway
for service in database controller agent-gateway; do
  for _ in $(seq 1 40); do
    state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
      "$project-$service-1" 2>/dev/null || true)
    test "$state" = healthy && break
    sleep 2
  done
  test "$(docker inspect --format '{{.State.Health.Status}}' "$project-$service-1")" = healthy
done
test "$(docker exec "$project-database-1" id -u)" = 70
test "$(docker exec "$project-controller-1" id -u)" = 10001
test "$(docker exec "$project-agent-gateway-1" id -u)" = 99
docker exec "$project-database-1" psql -U guardian -d guardian -Atc 'select 1' | grep -Fx 1

docker inspect "$project-database-1" "$project-controller-1" "$project-agent-gateway-1" >"$work/inspect.json"
docker logs "$project-database-1" >"$work/database.log" 2>&1
docker logs "$project-controller-1" >"$work/controller.log" 2>&1
docker logs "$project-agent-gateway-1" >"$work/gateway.log" 2>&1
for source in postgres-password database-url jwt-secret field-encryption-key enrollment-token proxy-auth restic-password; do
  if grep -F -f "$canonical/$source" "$work/inspect.json" "$work"/*.log >/dev/null; then
    echo "Secret content leaked through inspect or logs: $source" >&2
    exit 1
  fi
done
for container in "$project-database-1" "$project-controller-1" "$project-agent-gateway-1"; do
  docker exec "$container" sh -c 'tr "\0" "\n" </proc/1/cmdline' >"$work/$container.argv"
done
for source in postgres-password database-url jwt-secret field-encryption-key enrollment-token proxy-auth restic-password; do
  if grep -F -f "$canonical/$source" "$work"/*.argv >/dev/null; then
    echo "Secret content leaked through process argv: $source" >&2
    exit 1
  fi
done

"${compose[@]}" down
"${compose[@]}" up -d database controller
for service in database controller; do
  for _ in $(seq 1 40); do
    state=$(docker inspect --format '{{.State.Health.Status}}' "$project-$service-1" 2>/dev/null || true)
    test "$state" = healthy && break
    sleep 2
  done
  test "$(docker inspect --format '{{.State.Health.Status}}' "$project-$service-1")" = healthy
done
docker exec "$project-database-1" psql -U guardian -d guardian -Atc \
  'select version_num from alembic_version' | grep -Fx 0015_agent_maintenance
