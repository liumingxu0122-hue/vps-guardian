#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
cd "$root"
release_version="${VPS_GUARDIAN_RELEASE_VERSION:-v0.4.0-alpha.1}"
version="${release_version#v}"
python_version="${VPS_GUARDIAN_PYTHON_VERSION:-0.4.0a1}"
signing_private_key="${VPS_GUARDIAN_RELEASE_SIGNING_PRIVATE_KEY_FILE:-}"
trusted_public_key="$root/release/keys/v0.4-alpha-release-ed25519.pem"
trusted_key_id_file="$root/release/keys/v0.4-alpha-release-key-id.txt"
trusted_public_key_sha256="c9fe05398821dc580aaebcda4cea64f7bf9c998dc59c898b4fcdf79aacec37b4"
release_commit="$(git rev-parse HEAD)"
build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
build_id_prefix="${version}+$(printf '%s' "$release_commit" | cut -c1-12)"
for command in python3 npm go tar sha256sum git openssl realpath cmp tr; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing build command: $command" >&2; exit 69; }
done
if [ -n "$(git status --short)" ]; then
  echo "release artifacts require a clean Git worktree" >&2
  exit 73
fi
case "$release_version" in
  v0.4.0-alpha.1) ;;
  *) echo "release version must be v0.4.0-alpha.1" >&2; exit 64 ;;
esac
[ -n "$signing_private_key" ] || {
  echo "VPS_GUARDIAN_RELEASE_SIGNING_PRIVATE_KEY_FILE is required" >&2
  exit 78
}
[ -f "$signing_private_key" ] && [ ! -L "$signing_private_key" ] || {
  echo "release signing private key is missing or unsafe" >&2
  exit 78
}
private_realpath="$(realpath "$signing_private_key")"
case "$private_realpath" in
  "$root"|"$root"/*)
    echo "release signing private key must remain outside the repository" >&2
    exit 78
    ;;
esac
case "$(uname -s)" in
  Linux*)
    case "$(stat -c '%a' "$private_realpath")" in
      400|600) ;;
      *) echo "release signing private key mode must be 0400 or 0600" >&2; exit 78 ;;
    esac
    ;;
esac
canonical_public_key_sha256="$(git show HEAD:release/keys/v0.4-alpha-release-ed25519.pem | sha256sum | awk '{print $1}')"
[ "$canonical_public_key_sha256" = "$trusted_public_key_sha256" ] || {
    echo "repository release public key fingerprint mismatch" >&2
    exit 78
}
git show HEAD:release/keys/v0.4-alpha-release-key-id.txt |
  grep -Fx "ed25519-sha256:3e3d878e37f3ababd96827441be8dae17bb397b8012e8f7de65331f2356e524a" \
  >/dev/null

output="$root/artifacts"
if [ -e "$output/dist" ] || [ -e "$output/sbom" ] || [ -e "$output/public" ]; then
  echo "artifact output already exists; preserve it or move it before rebuilding" >&2
  exit 73
fi
umask 022
install -d -m 0755 "$output/dist" "$output/sbom" "$output/public"
key_check_dir="$(mktemp -d)"
trap 'rm -rf -- "$key_check_dir"' EXIT HUP INT TERM
git show HEAD:release/keys/v0.4-alpha-release-ed25519.pem > "$key_check_dir/trusted-public.pem"
git show HEAD:release/keys/v0.4-alpha-release-key-id.txt > "$key_check_dir/trusted-key-id.txt"
trusted_public_key="$key_check_dir/trusted-public.pem"
trusted_key_id_file="$key_check_dir/trusted-key-id.txt"
openssl pkey -in "$private_realpath" -pubout |
  tr -d '\r' > "$key_check_dir/generated-public.pem"
cmp "$key_check_dir/generated-public.pem" "$trusted_public_key" >/dev/null || {
  echo "release signing private key does not match the reviewed public key" >&2
  exit 78
}

python3 -m pip wheel --no-deps --wheel-dir "$output/dist" .
(cd "$output/dist" && test -n "$(find . -maxdepth 1 -name 'vps_guardian-*.whl' -print -quit)")
(cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -buildvcs=false -trimpath \
  -ldflags="-s -w -buildid= -X main.agentVersion=${version} -X main.buildCommit=${release_commit} -X main.buildTime=${build_time} -X main.buildID=${build_id_prefix}-linux-amd64 -X main.buildDirty=false" \
  -o "$output/dist/vps-guardian-agent-linux-amd64" .)
(cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -buildvcs=false -trimpath \
  -ldflags="-s -w -buildid= -X main.agentVersion=${version} -X main.buildCommit=${release_commit} -X main.buildTime=${build_time} -X main.buildID=${build_id_prefix}-linux-arm64 -X main.buildDirty=false" \
  -o "$output/dist/vps-guardian-agent-linux-arm64" .)
(cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
  -o "$output/dist/vps-guardian-net-helper-linux-amd64" ./nethelper)
(cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
  -o "$output/dist/vps-guardian-net-helper-linux-arm64" ./nethelper)
case "$(uname -s)" in
  Linux*)
    "$output/dist/vps-guardian-agent-linux-amd64" version |
      grep -Fx "git_sha=${release_commit}"
    "$output/dist/vps-guardian-agent-linux-amd64" --version |
      grep -Eq '^artifact_sha256=[a-f0-9]{64}$'
    ;;
  *)
    go version -m "$output/dist/vps-guardian-agent-linux-amd64" |
      grep -F "GOOS=linux" >/dev/null
    go version -m "$output/dist/vps-guardian-agent-linux-amd64" |
      grep -F "GOARCH=amd64" >/dev/null
    strings "$output/dist/vps-guardian-agent-linux-amd64" |
      grep -Fx "$release_commit" >/dev/null
    strings "$output/dist/vps-guardian-agent-linux-amd64" |
      grep -Fx "$version" >/dev/null
    ;;
esac
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
go version -m "$output/dist/vps-guardian-net-helper-linux-amd64" \
  > "$output/sbom/net-helper-build-info.txt"
go version -m "$output/dist/vps-guardian-net-helper-linux-arm64" \
  > "$output/sbom/net-helper-arm64-build-info.txt"
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
  VPS_GUARDIAN_RELEASE_VERSION="$version" \
  VPS_GUARDIAN_SOURCE_COMMIT="$release_commit" \
  VPS_GUARDIAN_BUILD_TIME="$build_time" \
  docker compose config --quiet
  VPS_GUARDIAN_RELEASE_VERSION="$version" \
  VPS_GUARDIAN_SOURCE_COMMIT="$release_commit" \
  VPS_GUARDIAN_BUILD_TIME="$build_time" \
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
public="$output/public"
installer_asset="vps-guardian-install-agent-${release_version}.sh"
maintenance_asset="vps-guardian-maintain-agent-${release_version}.sh"
agent_amd64_asset="vps-guardian-agent-${release_version}-linux-amd64"
agent_arm64_asset="vps-guardian-agent-${release_version}-linux-arm64"
helper_amd64_asset="vps-guardian-net-helper-${release_version}-linux-amd64"
helper_arm64_asset="vps-guardian-net-helper-${release_version}-linux-arm64"
manifest_asset="vps-guardian-install-manifest-${release_version}.txt"
manifest_signature_asset="${manifest_asset}.sig"
public_key_asset="vps-guardian-release-signing-key-${release_version}.pem"
key_id_asset="vps-guardian-release-signing-key-id-${release_version}.txt"
agent_metadata_asset="vps-guardian-agent-build-metadata-${release_version}.json"
agent_sbom_asset="vps-guardian-agent-sbom-${release_version}.cdx.json"
python_sbom_asset="vps-guardian-python-sbom-${release_version}.cdx.json"
web_sbom_asset="vps-guardian-web-sbom-${release_version}.cdx.json"
build_info_asset="vps-guardian-BUILD_INFO-${release_version}.txt"

install -m 0755 scripts/install-agent.sh "$public/$installer_asset"
install -m 0755 scripts/maintain-agent.sh "$public/$maintenance_asset"
install -m 0755 "$output/dist/vps-guardian-agent-linux-amd64" "$public/$agent_amd64_asset"
install -m 0755 "$output/dist/vps-guardian-agent-linux-arm64" "$public/$agent_arm64_asset"
install -m 0755 "$output/dist/vps-guardian-net-helper-linux-amd64" "$public/$helper_amd64_asset"
install -m 0755 "$output/dist/vps-guardian-net-helper-linux-arm64" "$public/$helper_arm64_asset"
python3 scripts/agent-release-metadata.py \
  --output "$public/$agent_metadata_asset" \
  --sbom-output "$public/$agent_sbom_asset" \
  --sbom-reference "$agent_sbom_asset" \
  --version "$version" \
  --git-sha "$release_commit" \
  --build-time "$build_time" \
  --build-id-prefix "$build_id_prefix" \
  --go-version "$(go version | awk '{print $3}')" \
  --dirty false \
  --artifact linux amd64 "$public/$agent_amd64_asset" \
  --artifact linux arm64 "$public/$agent_arm64_asset"
install -m 0644 "$output/sbom/python.cdx.json" "$public/$python_sbom_asset"
install -m 0644 "$output/sbom/web.cdx.json" "$public/$web_sbom_asset"
install -m 0644 "$output/BUILD_INFO" "$public/$build_info_asset"
install -m 0644 "$trusted_public_key" "$public/$public_key_asset"
install -m 0644 "$trusted_key_id_file" "$public/$key_id_asset"
install -m 0644 RELEASE_NOTES_v0.4.0-alpha.1.md \
  "$public/vps-guardian-release-notes-en-${release_version}.md"
install -m 0644 RELEASE_NOTES_v0.4.0-alpha.1.zh-CN.md \
  "$public/vps-guardian-release-notes-zh-CN-${release_version}.md"
install -m 0644 "$output/dist/vps-guardian-web-${release_version}.tar.gz" "$public/"
install -m 0644 "$output/dist/vps-guardian-compose-${release_version}.tar.gz" "$public/"
wheel_file="$(find "$output/dist" -maxdepth 1 -name 'vps_guardian-*.whl' -print -quit)"
install -m 0644 "$wheel_file" "$public/"
if [ -f "$output/sbom/images.BLOCKED.txt" ]; then
  install -m 0644 "$output/sbom/images.BLOCKED.txt" \
    "$public/vps-guardian-images-${release_version}.BLOCKED.txt"
fi
if [ -f "$output/sbom/image-sbom.BLOCKED.txt" ]; then
  install -m 0644 "$output/sbom/image-sbom.BLOCKED.txt" \
    "$public/vps-guardian-image-sbom-${release_version}.BLOCKED.txt"
fi
if [ -f "$output/sbom/controller-image.cdx.json" ]; then
  install -m 0644 "$output/sbom/controller-image.cdx.json" \
    "$public/vps-guardian-controller-image-sbom-${release_version}.cdx.json"
fi
if [ -f "$output/sbom/web-image.cdx.json" ]; then
  install -m 0644 "$output/sbom/web-image.cdx.json" \
    "$public/vps-guardian-web-image-sbom-${release_version}.cdx.json"
fi

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}
cat > "$public/$manifest_asset" <<EOF
version=${release_version}
key_id=$(cat "$trusted_key_id_file")
filename_install_agent=${installer_asset}
sha256_install_agent=$(sha256_file "$public/$installer_asset")
filename_maintain_agent=${maintenance_asset}
sha256_maintain_agent=$(sha256_file "$public/$maintenance_asset")
filename_linux_amd64=${agent_amd64_asset}
sha256_linux_amd64=$(sha256_file "$public/$agent_amd64_asset")
filename_linux_arm64=${agent_arm64_asset}
sha256_linux_arm64=$(sha256_file "$public/$agent_arm64_asset")
EOF
openssl pkeyutl -sign -inkey "$private_realpath" -rawin \
  -in "$public/$manifest_asset" -out "$public/$manifest_signature_asset"
openssl pkeyutl -verify -pubin -inkey "$trusted_public_key" -rawin \
  -in "$public/$manifest_asset" -sigfile "$public/$manifest_signature_asset"
(cd "$public" && \
  find . -maxdepth 1 -type f ! -name checksums.sha256 -exec sha256sum {} \; | \
  sed 's#  \./#  #' | sort > checksums.sha256 && \
  sha256sum --check --strict checksums.sha256)
! grep -R -l -- 'BEGIN .*PRIVATE KEY' "$public"
printf 'built signed public artifacts under %s\n' "$public"
