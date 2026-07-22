#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
cd "$root"
release_version="${VPS_GUARDIAN_RELEASE_VERSION:-v0.3.0-alpha.1}"
version="${release_version#v}"
python_version="${VPS_GUARDIAN_PYTHON_VERSION:-0.3.0a1}"
release_commit="$(git rev-parse HEAD)"
build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
(cd "$output/dist" && test -n "$(find . -maxdepth 1 -name 'vps_guardian-*.whl' -print -quit)")
(cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -buildvcs=false -trimpath \
  -ldflags="-s -w -buildid= -X main.agentVersion=${version} -X main.buildCommit=${release_commit} -X main.buildTime=${build_time}" \
  -o "$output/dist/vps-guardian-agent-linux-amd64" .)
(cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -buildvcs=false -trimpath \
  -ldflags="-s -w -buildid= -X main.agentVersion=${version} -X main.buildCommit=${release_commit} -X main.buildTime=${build_time}" \
  -o "$output/dist/vps-guardian-agent-linux-arm64" .)
(cd web && npm ci --ignore-scripts && npm run build)
tar -C web/dist -czf "$output/dist/vps-guardian-web-${release_version}.tar.gz" .
git archive --format=tar.gz \
  -o "$output/dist/vps-guardian-compose-${release_version}.tar.gz" HEAD
(cd "$output/dist" && wheel_file="$(find . -maxdepth 1 -name 'vps_guardian-*.whl' -print -quit)" && \
  python3 -m venv "$output/.wheel-check" && \
  if [ -x "$output/.wheel-check/bin/python" ]; then wheel_python="$output/.wheel-check/bin/python"; \
  elif [ -x "$output/.wheel-check/Scripts/python.exe" ]; then wheel_python="$output/.wheel-check/Scripts/python.exe"; \
  else echo 'wheel verification venv has no Python executable' >&2; exit 69; fi && \
  "$wheel_python" -m pip install --no-deps "$wheel_file" >/dev/null && \
  "$wheel_python" -c "import guardian; assert guardian.__version__ == '${python_version}'")
rm -rf "$output/.wheel-check"
(cd web && npm sbom --package-lock-only --sbom-format cyclonedx) \
  > "$output/sbom/web.cdx.json"
go version -m "$output/dist/vps-guardian-agent-linux-amd64" \
  > "$output/sbom/agent-build-info.txt"
go version -m "$output/dist/vps-guardian-agent-linux-arm64" \
  > "$output/sbom/agent-arm64-build-info.txt"

if command -v pip-audit >/dev/null 2>&1; then
  pip-audit --requirement requirements.lock --disable-pip \
    --format cyclonedx-json --output "$output/sbom/python.cdx.json"
elif python3 -m pip_audit --version >/dev/null 2>&1; then
  python3 -m pip_audit --requirement requirements.lock --disable-pip \
    --format cyclonedx-json --output "$output/sbom/python.cdx.json"
else
  printf '%s\n' 'BLOCKED: pip-audit is required to create the Python SBOM.' \
    > "$output/sbom/python-sbom.BLOCKED.txt"
  echo 'pip-audit is required to create the Python SBOM' >&2
  exit 69
fi
if command -v docker >/dev/null 2>&1; then
  docker compose config --quiet
  docker compose build database controller web
  docker image inspect vps-guardian-postgres vps-guardian-controller vps-guardian-web \
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

cat > "$output/BUILD_INFO" <<EOF
release_version=${release_version}
release_commit=${release_commit}
build_time_utc=${build_time}
python_version=$(python3 --version)
go_version=$(go version)
node_version=$(node --version 2>/dev/null || printf 'unavailable')
npm_version=$(npm --version)
docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || printf 'unavailable')
EOF
cp RELEASE_NOTES_v0.3.0-alpha.1.md \
  "$output/dist/vps-guardian-release-notes-en-${release_version}.md"
cp RELEASE_NOTES_v0.3.0-alpha.1.zh-CN.md \
  "$output/dist/vps-guardian-release-notes-zh-CN-${release_version}.md"
(cd "$output" && \
  { sha256sum BUILD_INFO; find dist sbom -type f -exec sha256sum {} \;; } | \
  sort > checksums.sha256)
printf 'built artifacts under %s\n' "$output"
