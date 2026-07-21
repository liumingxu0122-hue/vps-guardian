#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
cd "$root"
for command in python3 npm go tar sha256sum git; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing build command: $command" >&2; exit 69; }
done
if [ -n "$(git status --short)" ]; then
  echo "release artifacts require a clean Git worktree" >&2
  exit 73
fi
output="$root/artifacts"
if [ -e "$output/dist" ] || [ -e "$output/sbom" ] || [ -e "$output/checksums.sha256" ]; then
  echo "artifact output already exists; preserve it or move it before rebuilding" >&2
  exit 73
fi
umask 022
install -d -m 0755 "$output/dist" "$output/sbom"

python3 -m pip wheel --no-deps --wheel-dir "$output/dist" .
(cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
  -o "$output/dist/vps-guardian-agent-linux-amd64" .)
(cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
  -o "$output/dist/vps-guardian-agent-linux-arm64" .)
(cd web && npm ci --ignore-scripts && npm run build)
tar -C web/dist -czf "$output/dist/vps-guardian-web-0.1.0-alpha.1.tar.gz" .
git archive --format=tar.gz \
  -o "$output/dist/vps-guardian-compose-0.1.0-alpha.1.tar.gz" HEAD
(cd web && npm sbom --package-lock-only --sbom-format cyclonedx) \
  > "$output/sbom/web.cdx.json"
go version -m "$output/dist/vps-guardian-agent-linux-amd64" \
  > "$output/sbom/agent-build-info.txt"
go version -m "$output/dist/vps-guardian-agent-linux-arm64" \
  > "$output/sbom/agent-arm64-build-info.txt"

if command -v pip-audit >/dev/null 2>&1; then
  pip-audit --requirement requirements.lock --disable-pip \
    --format cyclonedx-json --output "$output/sbom/python.cdx.json"
else
  printf '%s\n' 'BLOCKED: pip-audit is not installed; requirements.lock remains the hashed Python inventory.' \
    > "$output/sbom/python-sbom.BLOCKED.txt"
fi
if command -v docker >/dev/null 2>&1; then
  docker compose build controller web
  docker image inspect vps-guardian-controller vps-guardian-web \
    --format '{{.Id}} user={{.Config.User}} healthcheck={{json .Config.Healthcheck}}' \
    > "$output/sbom/image-build-info.txt"
  if command -v syft >/dev/null 2>&1; then
    syft vps-guardian-controller -o cyclonedx-json="$output/sbom/controller-image.cdx.json"
    syft vps-guardian-web -o cyclonedx-json="$output/sbom/web-image.cdx.json"
  else
    printf '%s\n' 'BLOCKED: Syft is not installed; image SBOMs were not generated.' \
      > "$output/sbom/image-sbom.BLOCKED.txt"
  fi
else
  printf '%s\n' 'BLOCKED: Docker is not installed; images, runtime users, healthchecks, and image SBOMs require Linux staging.' \
    > "$output/sbom/images.BLOCKED.txt"
fi

printf 'release_commit=%s\n' "$(git rev-parse HEAD)" > "$output/BUILD_INFO"
(cd "$output" && \
  { sha256sum BUILD_INFO; find dist sbom -type f -exec sha256sum {} \;; } | \
  sort > checksums.sha256)
printf 'built artifacts under %s\n' "$output"
