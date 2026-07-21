#!/bin/sh
set -eu

[ "${VPS_GUARDIAN_EPHEMERAL_LIFECYCLE_TEST:-}" = '1' ] && [ -f /.dockerenv ] || {
  echo 'lifecycle behavior tests must run in the dedicated ephemeral container' >&2
  exit 77
}
[ "$(id -u)" -eq 0 ] || { echo 'lifecycle behavior tests require container root' >&2; exit 77; }

repo='/workspace'
upgrade="$repo/scripts/upgrade-controller.sh"
installer="$repo/scripts/install-controller.sh"
rollback="$repo/scripts/rollback-controller.sh"
fixture='/lifecycle-fixture'
stub_bin="$fixture/bin"
source_dir="$fixture/source"
fixed_release_id='20990101T000000Z'

fail() {
  echo "lifecycle behavior test failed: $1" >&2
  exit 1
}

expect_status() {
  expected_status="$1"
  shift
  set +e
  "$@" > "$fixture/command.out" 2>&1
  actual_status=$?
  set -e
  if [ "$actual_status" -ne "$expected_status" ]; then
    cat "$fixture/command.out" >&2
    fail "expected status $expected_status, received $actual_status"
  fi
}

ensure_guardian_identity() {
  if ! grep -q '^guardian:' /etc/group; then
    printf 'guardian:x:12345:\n' >> /etc/group
  fi
  if ! grep -q '^guardian:' /etc/passwd; then
    printf 'guardian:x:12345:12345:Guardian:/var/lib/vps-guardian:/usr/sbin/nologin\n' \
      >> /etc/passwd
  fi
  if ! grep -q '^guardian-release:' /etc/group; then
    printf 'guardian-release:x:12346:guardian,guardian-backup\n' >> /etc/group
  fi
  if ! grep -q '^guardian-database:' /etc/group; then
    printf 'guardian-database:x:12347:guardian,guardian-backup\n' >> /etc/group
  fi
  if ! grep -q '^guardian-backup:' /etc/group; then
    printf 'guardian-backup:x:12348:\n' >> /etc/group
  fi
  if ! grep -q '^guardian-backup:' /etc/passwd; then
    printf 'guardian-backup:x:12348:12348:Guardian Backup:/var/lib/vps-guardian-backup:/usr/sbin/nologin\n' \
      >> /etc/passwd
  fi
}

reset_fixture() {
  if [ -s "$fixture/systemd-state/controller.pid" ]; then
    kill "$(cat "$fixture/systemd-state/controller.pid")" >/dev/null 2>&1 || true
  fi
  rm -rf /opt/vps-guardian /var/lib/vps-guardian-units \
    /var/backups/vps-guardian-controller /etc/vps-guardian /run/vps-guardian \
    /var/lib/vps-guardian-lifecycle /etc/vps-guardian-backup-secrets \
    /outside-release "$fixture"
  rm -f /etc/systemd/system/vps-guardian-controller.service \
    /etc/systemd/system/vps-guardian-backup.service \
    /etc/systemd/system/vps-guardian-backup.timer \
    /etc/systemd/system/vps-guardian-backup-freshness.service \
    /etc/systemd/system/vps-guardian-backup-freshness.timer
  install -d -o root -g root -m 0755 /opt /etc/systemd/system
  install -d -o root -g root -m 0700 "$fixture" "$source_dir" "$stub_bin"
  for source_path in controller deploy/systemd runbooks scripts web; do
    install -d -o root -g root -m 0700 "$source_dir/$source_path"
    : > "$source_dir/$source_path/.fixture"
  done
  : > "$source_dir/pyproject.toml"
  : > "$source_dir/requirements-build.lock"
  : > "$source_dir/requirements.lock"
  : > "$source_dir/README.md"
  : > "$source_dir/web/package-lock.json"
  printf 'A\n' > "$source_dir/controller/test-revision"
  printf 'A\nB\n' > "$source_dir/controller/test-compatible-revisions"
  cp "$repo/scripts/release-manifest.py" "$source_dir/scripts/release-manifest.py"
  cp "$repo/scripts/run-backup-command.sh" "$source_dir/scripts/run-backup-command.sh"
  cp "$repo/scripts/run-systemd-backup.sh" "$source_dir/scripts/run-systemd-backup.sh"
  cp "$repo/scripts/systemd-backup-markers.py" "$source_dir/scripts/systemd-backup-markers.py"
  cp "$repo/deploy/systemd/vps-guardian-controller.service" \
    "$source_dir/deploy/systemd/vps-guardian-controller.service"
  cp "$repo/deploy/systemd/vps-guardian-backup.service" \
    "$source_dir/deploy/systemd/vps-guardian-backup.service"
  cp "$repo/deploy/systemd/vps-guardian-backup.timer" \
    "$source_dir/deploy/systemd/vps-guardian-backup.timer"
  cp "$repo/deploy/systemd/vps-guardian-backup-freshness.service" \
    "$source_dir/deploy/systemd/vps-guardian-backup-freshness.service"
  cp "$repo/deploy/systemd/vps-guardian-backup-freshness.timer" \
    "$source_dir/deploy/systemd/vps-guardian-backup-freshness.timer"
  git -C "$source_dir" init -q -b main
  git -C "$source_dir" config user.name 'VPS Guardian lifecycle test'
  git -C "$source_dir" config user.email 'lifecycle@guardian.invalid'
  git -C "$source_dir" add --all
  git -C "$source_dir" commit -q -m 'fixture release'
  install -d -o root -g guardian-database -m 0750 /etc/vps-guardian
  printf 'GUARDIAN_ENVIRONMENT=test\n' \
    > /etc/vps-guardian/controller.env
  chmod 0600 /etc/vps-guardian/controller.env
  printf 'sqlite:////var/lib/vps-guardian/test.db\n' \
    > /etc/vps-guardian/database-url
  chown root:guardian-database /etc/vps-guardian/database-url
  chmod 0640 /etc/vps-guardian/database-url
  printf 'test-only-signing-key\n' > /etc/vps-guardian/controller-ed25519.pem
  chown root:guardian /etc/vps-guardian/controller-ed25519.pem
  chmod 0640 /etc/vps-guardian/controller-ed25519.pem
  install -d -o root -g guardian-backup -m 0750 /etc/vps-guardian-backup-secrets
  printf '/var/lib/vps-guardian-backup/restic\n' \
    > /etc/vps-guardian-backup-secrets/restic-repository
  printf 'test-only-restic-password\n' \
    > /etc/vps-guardian-backup-secrets/restic-password
  chown root:guardian-backup /etc/vps-guardian-backup-secrets/*
  chmod 0640 /etc/vps-guardian-backup-secrets/*
  cat > "$stub_bin/date" <<EOF
#!/bin/sh
if [ -f '$fixture/date-counter' ]; then
  counter="\$(cat '$fixture/date-counter')"
  counter=\$((counter + 1))
  printf '%s\n' "\$counter" > '$fixture/date-counter'
  printf '20990101T%06dZ\n' "\$counter"
  exit 0
fi
printf '%s\\n' '$fixed_release_id'
EOF
  cat > "$stub_bin/tar" <<'EOF'
#!/bin/sh
if [ "${LIFECYCLE_REAL_TAR:-}" = '1' ]; then
  exec /bin/tar "$@"
fi
case " $* " in
  *' -cf '*) exit 0 ;;
  *) exit 91 ;;
esac
EOF
  for command in curl npm; do
    cat > "$stub_bin/$command" <<'EOF'
#!/bin/sh
exit 0
EOF
  done
  cat > "$stub_bin/su" <<'EOF'
#!/bin/sh
set -eu
fixture='/lifecycle-fixture'
command_text=''
for argument in "$@"; do command_text="$argument"; done
release_from_cd="$(printf '%s\n' "$command_text" | sed -n "s/.*cd '\([^']*\)'.*/\1/p")"
release_from_venv="$(printf '%s\n' "$command_text" | sed -n "s/.*venv --copies '\([^']*\)\/.venv'.*/\1/p")"
release_root="$release_from_cd"
case "$release_root" in */web) release_root="${release_root%/web}" ;; esac
if [ -n "$release_from_venv" ]; then release_root="$release_from_venv"; fi
compatible() {
  revision="$(cat "$fixture/db-revision")"
  grep -Fx "$revision" "$1/controller/test-compatible-revisions" >/dev/null
}
inject_after_action() {
  description="$1"
  [ -n "${LIFECYCLE_INJECT_MATCH:-}" ] && \
    [ ! -e "$fixture/injection-fired" ] || return 0
  case "$description" in
    *"$LIFECYCLE_INJECT_MATCH"*)
      : > "$fixture/injection-fired"
      kill -s "${LIFECYCLE_INJECT_SIGNAL:-KILL}" "$PPID"
      ;;
  esac
}
case "$command_text" in
  *'python3 -m venv --copies'*)
    install -d -m 0750 "$release_root/.venv/bin"
    for executable in alembic pip python uvicorn; do
      printf '#!/bin/sh\nexit 0\n' > "$release_root/.venv/bin/$executable"
      chmod 0750 "$release_root/.venv/bin/$executable"
    done
    ;;
  *'npm ci --ignore-scripts'*)
    install -d -m 0750 "$release_root/web/node_modules" "$release_root/web/dist"
    ;;
  *'alembic'*'upgrade head'*)
    cat "$release_root/controller/test-revision" > "$fixture/db-revision"
    inject_after_action 'alembic upgrade head'
    ;;
  *'alembic'*'current --check-heads'*) compatible "$release_root" ;;
  *'MigrationContext'*) cat "$fixture/db-revision" ;;
  *'from sqlalchemy'*|*'from guardian.api'*) compatible "$release_root" ;;
  *'run-backup-command.sh'*' controller '*) printf '{"verified":true}\n' ;;
  *'run-backup-command.sh'*) ;;
  *)
    echo "unexpected lifecycle su command: $command_text" >&2
    exit 96
    ;;
esac
EOF
  cat > "$stub_bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
fixture='/lifecycle-fixture'
state="$fixture/systemd-state"
install -d -m 0700 "$state"
printf '%s\n' "$*" >> "$fixture/systemctl.log"
inject_after_action() {
  description="$1"
  [ -n "${LIFECYCLE_INJECT_MATCH:-}" ] && \
    [ ! -e "$fixture/injection-fired" ] || return 0
  case "$description" in
    *"$LIFECYCLE_INJECT_MATCH"*)
      : > "$fixture/injection-fired"
      kill -s "${LIFECYCLE_INJECT_SIGNAL:-KILL}" "$PPID"
      ;;
  esac
}
stop_unit() {
  unit="$1"
  if [ "$unit" = 'vps-guardian-controller.service' ] && [ -s "$state/controller.pid" ]; then
    kill "$(cat "$state/controller.pid")" >/dev/null 2>&1 || true
    rm -f "$state/controller.pid"
  fi
  printf 'inactive\n' > "$state/$unit"
}
start_unit() {
  unit="$1"
  if [ "$unit" = 'vps-guardian-controller.service' ]; then
    stop_unit "$unit"
    target="$(readlink -f /opt/vps-guardian/current)"
    # systemd starts the Controller outside the caller's lifecycle lock.
    # Close the fixture's inherited descriptor before spawning its process.
    exec 9>&-
    nohup sh -c "cd '$target' && exec sleep 300" >/dev/null 2>&1 &
    printf '%s\n' "$!" > "$state/controller.pid"
    attempts=0
    while [ "$(readlink -f "/proc/$!/cwd" 2>/dev/null || true)" != "$target" ]; do
      attempts=$((attempts + 1))
      [ "$attempts" -lt 50 ] || exit 98
      sleep 0.01
    done
  fi
  printf 'active\n' > "$state/$unit"
}
verb="$1"
shift
case "$verb" in
  is-active)
    [ "${1:-}" = '--quiet' ] && shift
    [ "$(cat "$state/$1" 2>/dev/null || true)" = 'active' ]
    ;;
  is-failed)
    [ "${1:-}" = '--quiet' ] && shift
    [ "$(cat "$state/$1" 2>/dev/null || true)" = 'failed' ]
    ;;
  stop)
    description="stop $*"
    for unit in "$@"; do stop_unit "$unit"; done
    inject_after_action "$description"
    ;;
  start|restart)
    description="$verb $*"
    for unit in "$@"; do start_unit "$unit"; done
    inject_after_action "$description"
    ;;
  enable)
    if [ "${1:-}" = '--now' ]; then
      shift
      for unit in "$@"; do start_unit "$unit"; done
    fi
    ;;
  disable)
    if [ "${1:-}" = '--now' ]; then
      shift
      for unit in "$@"; do stop_unit "$unit"; done
    fi
    ;;
  daemon-reload) ;;
  show)
    cat "$state/controller.pid"
    ;;
  *) echo "unexpected systemctl command: $verb $*" >&2; exit 97 ;;
esac
EOF
  chmod 0755 "$stub_bin/date" "$stub_bin/tar" "$stub_bin/curl" "$stub_bin/npm" \
    "$stub_bin/su" "$stub_bin/systemctl"
  printf 'A\n' > "$fixture/db-revision"
  : > "$fixture/systemctl.log"
}

write_installed_units() {
  owner="$1"
  for unit in vps-guardian-controller.service vps-guardian-backup.service vps-guardian-backup.timer; do
    printf 'trusted installed unit: %s\n' "$unit" > "/etc/systemd/system/$unit"
    chown "$owner" "/etc/systemd/system/$unit"
    chmod 0644 "/etc/systemd/system/$unit"
  done
}

make_layout() {
  layout="$1"
  install -d -o root -g root -m 0755 /opt/vps-guardian
  install -d -o root -g root -m 0755 /opt/vps-guardian/releases
  install -d -o guardian -g guardian -m 0750 \
    /opt/vps-guardian/releases/legacy-release
  ln -s /opt/vps-guardian/releases/legacy-release /opt/vps-guardian/current
  if [ "$layout" = 'legacy' ]; then
    chown guardian:guardian /opt/vps-guardian/releases /opt/vps-guardian
    chmod 0750 /opt/vps-guardian/releases /opt/vps-guardian
  fi
}

run_upgrade() {
  PATH="$stub_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$upgrade" --source "$source_dir" --execute --approval-id test-approval \
      --confirm 'UPGRADE VPS GUARDIAN'
}

run_real_install() {
  LIFECYCLE_REAL_TAR=1 \
  LIFECYCLE_INJECT_MATCH="${LIFECYCLE_INJECT_MATCH:-}" \
  LIFECYCLE_INJECT_SIGNAL="${LIFECYCLE_INJECT_SIGNAL:-}" \
  PATH="$stub_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$installer" --source "$source_dir" --execute
}

run_real_upgrade() {
  LIFECYCLE_REAL_TAR=1 \
  LIFECYCLE_INJECT_MATCH="${LIFECYCLE_INJECT_MATCH:-}" \
  LIFECYCLE_INJECT_SIGNAL="${LIFECYCLE_INJECT_SIGNAL:-}" \
  PATH="$stub_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$upgrade" --source "$source_dir" --execute --approval-id test-approval \
      --confirm 'UPGRADE VPS GUARDIAN'
}

run_upgrade_recovery() {
  PATH="$stub_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$upgrade" --execute --approval-id test-approval \
      --confirm 'UPGRADE VPS GUARDIAN'
}

run_real_rollback() {
  rollback_release="$1"
  LIFECYCLE_INJECT_MATCH="${LIFECYCLE_INJECT_MATCH:-}" \
  LIFECYCLE_INJECT_SIGNAL="${LIFECYCLE_INJECT_SIGNAL:-}" \
  PATH="$stub_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$rollback" --release "$rollback_release" --execute \
      --approval-id test-approval --confirm 'ROLLBACK VPS GUARDIAN'
}

run_rollback_recovery() {
  PATH="$stub_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$rollback" --execute --approval-id test-approval \
      --confirm 'ROLLBACK VPS GUARDIAN'
}

prepare_revision() {
  revision="$1"
  compatible_revisions="$2"
  printf '%s\n' "$revision" > "$source_dir/controller/test-revision"
  printf '%b' "$compatible_revisions" > "$source_dir/controller/test-compatible-revisions"
  git -C "$source_dir" add controller/test-revision controller/test-compatible-revisions
  git -C "$source_dir" commit -q -m "fixture release $revision"
}

assert_runtime() {
  expected_release="$1"
  [ "$(readlink -- /opt/vps-guardian/current)" = "$expected_release" ] || \
    fail "current release is not $expected_release"
  [ "$(cat "$fixture/systemd-state/vps-guardian-controller.service")" = 'active' ] || \
    fail 'Controller is not active'
  [ "$(cat "$fixture/systemd-state/vps-guardian-backup.timer")" = 'active' ] || \
    fail 'backup timer is not active'
  [ "$(cat "$fixture/systemd-state/vps-guardian-backup-freshness.timer")" = 'active' ] || \
    fail 'backup freshness timer is not active'
  controller_pid="$(cat "$fixture/systemd-state/controller.pid")"
  [ "$(readlink -f "/proc/$controller_pid/cwd")" = "$expected_release" ] || \
    fail 'running Controller does not match current release'
  [ ! -e /var/lib/vps-guardian-lifecycle/controller.json ] || \
    fail 'completed lifecycle left a journal'
}

ensure_guardian_identity

# Exact legacy ownership is migrated and the active release becomes immutable.
# Its untrusted units never become the root snapshot.
reset_fixture
make_layout legacy
write_installed_units root:root
install -d -o guardian -g guardian -m 0750 \
  /opt/vps-guardian/releases/legacy-release/deploy/systemd
for unit in vps-guardian-controller.service vps-guardian-backup.service vps-guardian-backup.timer; do
  printf 'malicious legacy unit: %s\n' "$unit" > \
    "/opt/vps-guardian/releases/legacy-release/deploy/systemd/$unit"
done
expect_status 91 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian)" = 'root:root:755' ] || \
  fail 'legacy install root was not migrated'
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian/releases)" = 'root:root:755' ] || \
  fail 'legacy releases root was not migrated'
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian/releases/legacy-release)" = \
  'root:guardian-release:550' ] || fail 'legacy release subtree was not hardened'
for unit in vps-guardian-controller.service vps-guardian-backup.service vps-guardian-backup.timer; do
  snapshot="/var/lib/vps-guardian-units/legacy-release/$unit"
  cmp -s "/etc/systemd/system/$unit" "$snapshot" || \
    fail "snapshot did not come from installed root unit: $unit"
  if cmp -s "/opt/vps-guardian/releases/legacy-release/deploy/systemd/$unit" \
    "$snapshot"; then
    fail "legacy release unit was trusted: $unit"
  fi
done

# A modern layout is accepted and its active release is hardened.
reset_fixture
make_layout modern
write_installed_units root:root
expect_status 91 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian)" = 'root:root:755' ] || \
  fail 'modern install root changed'
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian/releases/legacy-release)" = \
  'root:guardian-release:550' ] || fail 'modern release subtree was not hardened'

# The exact root-owned mode-0750 interruption state is completed on retry.
reset_fixture
make_layout modern
chmod 0750 /opt/vps-guardian /opt/vps-guardian/releases
write_installed_units root:root
expect_status 91 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian)" = 'root:root:755' ] || \
  fail 'interrupted install-root migration was not completed'
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian/releases)" = 'root:root:755' ] || \
  fail 'interrupted releases-root migration was not completed'

# An archive extraction failure is observed before candidate activation.
reset_fixture
make_layout modern
write_installed_units root:root
cat > "$stub_bin/tar" <<'EOF'
#!/bin/sh
exit 92
EOF
chmod 0755 "$stub_bin/tar"
expect_status 92 run_upgrade

# A guardian-owned current symlink is not an exact legacy layout. No ownership
# migration is allowed before this failure.
reset_fixture
make_layout legacy
chown -h guardian:guardian /opt/vps-guardian/current
write_installed_units root:root
expect_status 77 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian)" = 'guardian:guardian:750' ] || \
  fail 'unsafe legacy parent was modified'

# Unexpected ownership/mode cannot be laundered into a trusted release root.
reset_fixture
make_layout modern
chown guardian:guardian /opt/vps-guardian/releases
chmod 0755 /opt/vps-guardian/releases
write_installed_units root:root
expect_status 77 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian/releases)" = \
  'guardian:guardian:755' ] || fail 'unexpected release-root state was modified'

# Installed unit files must already be root-controlled; legacy release units do
# not provide a fallback.
reset_fixture
make_layout legacy
write_installed_units guardian:guardian
expect_status 66 run_upgrade
[ ! -e /var/lib/vps-guardian-units/legacy-release ] || \
  fail 'unsafe installed units produced a root snapshot'

# Non-canonical local repositories and multiline database URL files fail before
# any lifecycle migration.
reset_fixture
make_layout legacy
write_installed_units root:root
printf '/var/lib/vps-guardian/restic/../../../var/backups/escape\n' \
  > /etc/vps-guardian-backup-secrets/restic-repository
expect_status 77 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian)" = 'guardian:guardian:750' ] || \
  fail 'invalid local repository changed the legacy install root'

reset_fixture
make_layout legacy
write_installed_units root:root
printf 'sqlite:////var/lib/vps-guardian/test.db\njunk\n' \
  > /etc/vps-guardian-backup-secrets/database-url
expect_status 77 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian)" = 'guardian:guardian:750' ] || \
  fail 'multiline database URL changed the legacy install root'

# The service environment must never carry the database URL in /proc. Only the
# fixed root-controlled URL file is accepted.
reset_fixture
make_layout legacy
write_installed_units root:root
printf 'GUARDIAN_DATABASE_URL=sqlite:////var/lib/vps-guardian/test.db\n' \
  >> /etc/vps-guardian/controller.env
expect_status 77 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian)" = 'guardian:guardian:750' ] || \
  fail 'legacy database environment rejection changed the install root'

# current may reference only one real, absolute child of releases.
for invalid_kind in outside nested alias dangling; do
  reset_fixture
  make_layout modern
  write_installed_units root:root
  rm -f /opt/vps-guardian/current
  case "$invalid_kind" in
    outside)
      install -d -o guardian -g guardian -m 0750 /outside-release
      ln -s /outside-release /opt/vps-guardian/current
      ;;
    nested)
      install -d -o guardian -g guardian -m 0750 \
        /opt/vps-guardian/releases/nested/release
      ln -s /opt/vps-guardian/releases/nested/release /opt/vps-guardian/current
      ;;
    alias)
      ln -s /opt/vps-guardian/releases/legacy-release \
        /opt/vps-guardian/releases/alias-release
      ln -s /opt/vps-guardian/releases/alias-release /opt/vps-guardian/current
      ;;
    dangling)
      ln -s /opt/vps-guardian/releases/missing-release /opt/vps-guardian/current
      ;;
  esac
  expect_status 65 run_upgrade
done

# A dangling current link blocks a fresh install before account, Secret, or
# release mutations are attempted.
reset_fixture
install -d -o root -g root -m 0755 /opt/vps-guardian
ln -s /opt/vps-guardian/releases/missing /opt/vps-guardian/current
install -d -o root -g root -m 0700 "$source_dir/web"
: > "$source_dir/web/package-lock.json"
expect_status 73 env \
  PATH="$stub_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  sh "$installer" --source "$source_dir" --execute

# Rollback rejects nested and alias paths before consulting unit snapshots.
reset_fixture
make_layout modern
install -d -o guardian -g guardian -m 0750 \
  /opt/vps-guardian/releases/nested/target/.venv/bin
: > /opt/vps-guardian/releases/nested/target/.venv/bin/uvicorn
chmod 0755 /opt/vps-guardian/releases/nested/target/.venv/bin/uvicorn
expect_status 65 sh "$rollback" \
  --release /opt/vps-guardian/releases/nested/target --execute \
  --approval-id test-approval --confirm 'ROLLBACK VPS GUARDIAN'

# A plausible release and root unit snapshot are still not rollback-eligible
# without the root-controlled COMMITTED marker and checksum manifest.
reset_fixture
make_layout modern
chown -hR root:root /opt/vps-guardian/releases/legacy-release
find /opt/vps-guardian/releases/legacy-release -type d -exec chmod 0555 {} \;
install -d -o root -g root -m 0555 \
  /opt/vps-guardian/releases/legacy-release/.venv/bin
: > /opt/vps-guardian/releases/legacy-release/.venv/bin/uvicorn
chmod 0555 /opt/vps-guardian/releases/legacy-release/.venv/bin/uvicorn
install -d -o root -g root -m 0700 /var/lib/vps-guardian-units/legacy-release
write_installed_units root:root
for unit in vps-guardian-controller.service vps-guardian-backup.service vps-guardian-backup.timer; do
  install -o root -g root -m 0644 "/etc/systemd/system/$unit" \
    "/var/lib/vps-guardian-units/legacy-release/$unit"
done
expect_status 66 sh "$rollback" \
  --release /opt/vps-guardian/releases/legacy-release --execute \
  --approval-id test-approval --confirm 'ROLLBACK VPS GUARDIAN'

# Holding the shared lock makes a second lifecycle operation exit before it can
# migrate the legacy parent.
reset_fixture
make_layout legacy
write_installed_units root:root
install -d -o root -g root -m 0755 /run/vps-guardian
(umask 077; : > /run/vps-guardian/controller-lifecycle.lock)
exec 8<>/run/vps-guardian/controller-lifecycle.lock
flock -n 8
expect_status 75 run_upgrade
[ "$(stat -c '%U:%G:%a' /opt/vps-guardian)" = 'guardian:guardian:750' ] || \
  fail 'contended lifecycle operation changed the install root'
flock -u 8

# Complete A install, A -> B, B -> A, and B redeployment with an additive
# schema that remains compatible with both releases.
reset_fixture
printf '0\n' > "$fixture/date-counter"
run_real_install
a_release="$(readlink -- /opt/vps-guardian/current)"
assert_runtime "$a_release"
prepare_revision B 'A\nB\n'
run_real_upgrade
b_release="$(readlink -- /opt/vps-guardian/current)"
[ "$b_release" != "$a_release" ] || fail 'A -> B did not create a new release'
[ "$(cat "$fixture/db-revision")" = 'B' ] || fail 'A -> B did not migrate the schema'
assert_runtime "$b_release"
run_real_rollback "$a_release"
[ "$(cat "$fixture/db-revision")" = 'B' ] || fail 'B -> A performed an automatic downgrade'
assert_runtime "$a_release"
run_real_upgrade
b_redeployment="$(readlink -- /opt/vps-guardian/current)"
[ "$b_redeployment" != "$b_release" ] || fail 'B redeployment reused the old release path'
[ "$(cat "$b_redeployment/SOURCE_COMMIT")" = "$(git -C "$source_dir" rev-parse HEAD)" ] || \
  fail 'B redeployment source commit is wrong'
assert_runtime "$b_redeployment"

# SIGKILL immediately after timer stop must still leave a durable journal.
# Recovery is intentionally invoked without --source.
reset_fixture
printf '0\n' > "$fixture/date-counter"
run_real_install
a_release="$(readlink -- /opt/vps-guardian/current)"
prepare_revision B 'A\nB\n'
export LIFECYCLE_INJECT_MATCH='stop vps-guardian-backup.timer'
export LIFECYCLE_INJECT_SIGNAL='KILL'
expect_status 137 run_real_upgrade
unset LIFECYCLE_INJECT_MATCH LIFECYCLE_INJECT_SIGNAL
[ -f /var/lib/vps-guardian-lifecycle/controller.json ] || \
  fail 'timer-stop SIGKILL did not leave a durable journal'
run_upgrade_recovery
assert_runtime "$a_release"

# A candidate that was already started is stopped before recovery mutates units
# or current. The systemctl log makes the ordering observable.
reset_fixture
printf '0\n' > "$fixture/date-counter"
run_real_install
a_release="$(readlink -- /opt/vps-guardian/current)"
prepare_revision B 'A\nB\n'
export LIFECYCLE_INJECT_MATCH='restart vps-guardian-controller.service'
export LIFECYCLE_INJECT_SIGNAL='KILL'
expect_status 137 run_real_upgrade
unset LIFECYCLE_INJECT_MATCH LIFECYCLE_INJECT_SIGNAL
: > "$fixture/systemctl.log"
run_upgrade_recovery
controller_stop_line="$(grep -n '^stop vps-guardian-controller.service$' \
  "$fixture/systemctl.log" | head -n 1 | cut -d: -f1)"
daemon_reload_line="$(grep -n '^daemon-reload$' "$fixture/systemctl.log" | \
  head -n 1 | cut -d: -f1)"
[ -n "$controller_stop_line" ] && [ -n "$daemon_reload_line" ] && \
  [ "$controller_stop_line" -lt "$daemon_reload_line" ] || \
  fail 'recovery did not stop the candidate before restoring units'
assert_runtime "$a_release"

# A migrated schema that the previous release cannot read is a hard stop. Both
# Controller and timer remain inactive and recovery_started stays durable.
reset_fixture
printf '0\n' > "$fixture/date-counter"
prepare_revision A 'A\n'
run_real_install
prepare_revision B 'B\n'
export LIFECYCLE_INJECT_MATCH='alembic upgrade head'
export LIFECYCLE_INJECT_SIGNAL='KILL'
expect_status 137 run_real_upgrade
unset LIFECYCLE_INJECT_MATCH LIFECYCLE_INJECT_SIGNAL
[ "$(cat "$fixture/db-revision")" = 'B' ] || fail 'schema injection did not reach B'
expect_status 72 run_upgrade_recovery
[ "$(cat "$fixture/systemd-state/vps-guardian-controller.service")" = 'inactive' ] || \
  fail 'schema-incompatible recovery restarted the Controller'
  [ "$(cat "$fixture/systemd-state/vps-guardian-backup.timer")" = 'inactive' ] || \
    fail 'schema-incompatible recovery restarted the backup timer'
  [ "$(cat "$fixture/systemd-state/vps-guardian-backup-freshness.timer")" = 'inactive' ] || \
    fail 'schema-incompatible recovery restarted the backup freshness timer'
grep -Fq '"phase": "recovery_started"' \
  /var/lib/vps-guardian-lifecycle/controller.json || \
  fail 'schema-incompatible recovery did not retain recovery_started'

# TERM uses the same helper from the EXIT trap and restores A without leaving a
# transaction behind.
reset_fixture
printf '0\n' > "$fixture/date-counter"
run_real_install
a_release="$(readlink -- /opt/vps-guardian/current)"
prepare_revision B 'A\nB\n'
export LIFECYCLE_INJECT_MATCH='restart vps-guardian-controller.service'
export LIFECYCLE_INJECT_SIGNAL='TERM'
expect_status 75 run_real_upgrade
unset LIFECYCLE_INJECT_MATCH LIFECYCLE_INJECT_SIGNAL
assert_runtime "$a_release"

# Rollback recovery also derives both releases and snapshots only from its
# journal; no --release argument is supplied on retry.
reset_fixture
printf '0\n' > "$fixture/date-counter"
run_real_install
a_release="$(readlink -- /opt/vps-guardian/current)"
prepare_revision B 'A\nB\n'
run_real_upgrade
b_release="$(readlink -- /opt/vps-guardian/current)"
export LIFECYCLE_INJECT_MATCH='restart vps-guardian-controller.service'
export LIFECYCLE_INJECT_SIGNAL='KILL'
expect_status 137 run_real_rollback "$a_release"
unset LIFECYCLE_INJECT_MATCH LIFECYCLE_INJECT_SIGNAL
run_rollback_recovery
assert_runtime "$b_release"

echo 'controller lifecycle behavior tests: PASS'
