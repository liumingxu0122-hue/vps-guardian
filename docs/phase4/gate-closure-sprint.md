# Phase 4 Gate Closure Sprint

This report records the hard-gate work performed after the Phase 4 RC1 preflight.
It adds no unrelated product feature and authorizes no real Staging or Production
deployment. Secret values, user addresses, private addresses, Agent identities,
TOTP material, passwords, and recovery material are excluded.

## Evidence boundary

- Original RC source: `108d7880e9f5f1b5455245be927ea7fb02d8346f`.
- Pre-sprint branch head: `93473716a3b6932a74de4e673e45baad73c7e7a6`.
- Branch: `feat/phase4-completion-ui-v2`.
- Audit date: 2026-07-25.
- Existing authenticated Staging remained on its old images and schema.
- No database migration, container switch, Owner mutation, TOTP mutation, Agent
  installation, certificate mutation, notification delivery, DNS change, Komari
  change, proxy-node change, or Production action occurred.
- The existing PostgreSQL backup, fixed source archive, SHA-256 evidence, and local
  Restic snapshot
  `faa545acdcdf570c379f8166a62a2ee04490add2faf02487d8ad7ec8e82c1759`
  were preserved.

## A. Identity recovery audit

The real Staging database is still at `0007_multivps_alerts`.

| Check | Current real Staging result |
| --- | --- |
| Active Owner | 1 |
| Disabled Owner | 0 |
| Independent recovery Owner | 0 |
| TOTP-enabled Owner | 0 |
| Disabled Operator | 1 |
| `session_version` column | Absent in active schema |
| Server-side session table | Absent |
| Invite table/workflow | Absent |
| Password-reset table/workflow | Absent |
| Last-active-Owner protection | Implemented and tested in candidate code |
| Password rotation | Owner-only candidate endpoint; reauthentication required |
| Session revocation | Candidate `session_version` increment; active schema cannot use it |
| TOTP provisioning | Interactive administration command only |
| Recovery-code lifecycle | Not implemented |

Browser and bearer sessions are stateless JWTs. After migration `0008`, incrementing
`session_version` rejects every older token and cookie at the next request. The
candidate test suite proves an old bearer token returns `401` after revocation.
The same mechanism is used by password rotation, role/scope changes, and account
disablement.

No recovery Owner was created. The current environment has no approved channel
that can deliver a new password, TOTP provisioning URI, or recovery material
without chat, logs, command arguments, files, or screen capture. This gate stops
at the required human step.

### HUMAN ACTION REQUIRED: identity

On a trusted interactive terminal with transcript/history/screen capture disabled:

1. provide and approve an independent recovery-Owner email identifier;
2. establish a secure out-of-band credential-delivery session;
3. create the recovery Owner interactively, without password arguments or files;
4. enroll and verify TOTP directly with the intended human custodian;
5. decide how recovery codes will be implemented, because the current product has
   no recovery-code lifecycle;
6. verify the recovery Owner login and a wrong-TOTP rejection;
7. after candidate migration, rotate the existing Owner password interactively;
8. revoke sessions and verify the old password and old cookie return `401`;
9. verify the new password, correct TOTP, recovery Owner, and audit events;
10. confirm that at least one Owner remains usable throughout.

Decision: **HUMAN ACTION REQUIRED / NO-GO**.

## B. Agent version and immutable provenance

The gate-closure change adds:

- `guardian-agent version` and `guardian-agent --version`;
- command dispatch before configuration loading or Agent-loop startup;
- semantic version, full Git SHA, build ID, build time, Go version, target
  OS/architecture, dirty state, and runtime-calculated executable SHA-256;
- a regression test whose configuration and run hooks fail the test if either
  version command enters Agent startup;
- authenticated heartbeat build metadata;
- nullable Controller storage fields for backward compatibility with old Agents;
- reversible migration `0009_agent_provenance`;
- Agent API and management-page version, build SHA, and platform display;
- a checksummed Agent release manifest and CycloneDX document for Linux
  `amd64` and `arm64`;
- CI-built Agent artifacts with immutable build metadata;
- OCI version, revision, created, source, and license labels for Controller,
  Backup, Web, and Database images, with a CI label gate.

The executable SHA-256 is calculated from the running binary. It is not embedded
into the binary, which would create an impossible self-referential hash.

Old Agents remain accepted because heartbeat build metadata is optional. New
release Agents report the complete object. A heartbeat that reports different
top-level and build versions is rejected.

Pre-commit validation passed:

- `gofmt`, `go vet`, and all Agent tests in a no-network container;
- both version commands in a separate no-network runtime;
- the reported artifact SHA-256 matched the actual executable;
- all Python tests, Ruff, and Mypy;
- Web typecheck, unit tests, and production build;
- migration `0007 → 0009 → 0008 → 0009` against an isolated restore of the real
  Staging dump;
- all eight provenance columns were present after upgrade and absent after
  downgrade;
- the two restored Agent rows remained unchanged in count.

The first isolated Go test attempt used a non-executable temporary filesystem and
failed to launch the generated test binary. Retrying with an executable,
no-network tmpfs passed. The first isolated PostgreSQL attempt trusted
`pg_isready`, which can succeed before the requested database exists; cleanup ran,
and the retry waited for an actual SQL query before restore. Neither correction
connected to or changed the active database or Agent.

Gate-closure implementation commit
`7a4a89349505ec44e890031f163a6036aead881c` passed both CI executions:

- push run `30165806427`;
- pull-request run `30165807963`.

Both runs passed Agent formatting/tests/release artifact generation, Python
lint/type/full tests/dependency audit/wheel verification, Web type/unit/build/audit,
14 browser visual cases, Gitleaks, Compose overlays, four-image builds, OCI label
checks, source/image SBOM generation, Critical-zero gates, and fixable-High-zero
gates. A local Playwright invocation reached all 14 cases but did not exit during
runner teardown; no test failure was reported. The independent CI browser job
completed normally, so the local teardown hang is retained as a tooling anomaly,
not used as the passing evidence.

Decision: **GO in code; real installed-Agent validation pending approved Staging
deployment**.

## C. Off-site Restic requirement check

The backup implementation already supports controlled file-based S3 credentials:

- `RESTIC_REPOSITORY_FILE`;
- `RESTIC_PASSWORD_FILE`;
- `AWS_ACCESS_KEY_ID_FILE`;
- `AWS_SECRET_ACCESS_KEY_FILE`;
- `AWS_DEFAULT_REGION_FILE`.

It rejects credentials embedded in repository URLs, non-TLS S3 endpoints,
incomplete credential-file sets, ambient AWS credentials, symlinks, non-root
ownership, and broad file modes. Credential values are injected only into the
Restic child process environment.

`deploy/offsite-backup.compose.yml` maps the five required files into the Backup
container without putting their contents in Compose environment values. It also
clears the inherited local-repository setting. The overlay fails configuration
unless `GUARDIAN_OFFSITE_SECRETS_DIR` is explicitly set.

Real Staging has none of the five off-site Secret files. Its only Restic repository
is on the Controller host. The successful local snapshot/check/restore remains
local recovery evidence only.

### HUMAN ACTION REQUIRED: off-site DR

The recovery owner must provide, through a protected host-side injection channel:

| Secret | Required content |
| --- | --- |
| Restic repository | Credential-free `s3:https://.../bucket/path` |
| Restic password | Dedicated repository password |
| Access-key ID | Least-privilege object-storage access key |
| Secret access key | Matching protected secret |
| Region | Current S3/R2 region identifier |

Files must be root-owned regular files, not symlinks, with an accepted mode such
as `0400`, `0440`, `0600`, or `0640`. Compose-mounted `/run/secrets` files may use
the controlled `0444` mode. The repository must be in a different failure domain.

After injection, create a new snapshot and run `snapshots`, `check`, and
`check --read-data` when approved. Restore into an independent PostgreSQL,
Controller, and Web project with separate networks and volumes; validate
migration, users, hosts, alerts, incidents, approvals, audit, CRL, and notification
references; then record snapshot ID, bytes, RPO, RTO, restore duration, and hashes.

Decision: **HUMAN ACTION REQUIRED / NO-GO**.

## D. Real notification-channel requirement check

Real Staging currently has one disabled webhook definition, six historical
`delivered` rows, external delivery disabled, and no Telegram/Discord/SMTP Secret
candidate files. Historical rows do not prove two independent current channels.

Notification configuration accepts environment/file references only. Resolved
values are not stored in the channel row. The UI lists channel type and enabled
state, not resolved Secret values. Retry and dead-letter behavior is implemented,
but no real closure event was executed in this sprint.

`deploy/notification-secrets.compose.yml` provides an explicit read-only,
no-auto-create bind mount. It fails configuration unless
`GUARDIAN_NOTIFICATION_SECRETS_DIR` is set. Channel rows must refer only to files
below `/run/notification-secrets` or to explicitly injected environment names.

### HUMAN ACTION REQUIRED: notifications

Provide two independent channel credential sets through protected injection,
preferably Telegram plus Discord or SMTP. Approve the recipients and the
non-production event window. Then exercise real Warning, Critical, recovery,
Agent-offline, incident, escalation, approval, backup-failure, delivery-failure,
retry, and dead-letter events. Record latency, attempts, final state, audit rows,
delivery UI, and Overview failure indication. A test-message-only result does not
pass.

Decision: **HUMAN ACTION REQUIRED / NO-GO**.

## E. Test Agent and low-risk nodes

The sanitized inventory and provisional selections are recorded in
[node-candidate-inventory.md](node-candidate-inventory.md).

- Dedicated certificate-test candidate: `staging-agent`, conditional on confirming
  that only its fixture identity is changed and its rollback unit is available.
- Provisional Batch 1: `US-native-02`, `US-native-05`.
- Provisional Batch 2: `HK-native-01`, `US-native-01`.

These are proposals, not approvals. Proxy-business status, direct rollback access,
init system, and Docker state are not proven for the remote candidates. No node was
installed, enrolled, upgraded, revoked, or otherwise changed.

Decision: **HUMAN ACTION REQUIRED**.

## Gate roll-up

| Gate | Decision | Blocking evidence |
| --- | --- | --- |
| Identity Recovery | HUMAN ACTION REQUIRED / NO-GO | One Owner, no TOTP, no recovery-code lifecycle or safe delivery |
| Agent Provenance | GO in code | Real installed binary not changed |
| Off-site DR | HUMAN ACTION REQUIRED / NO-GO | No remote backend Secret or isolated restore |
| Notification | HUMAN ACTION REQUIRED / NO-GO | No two real credential sets or event closure |
| Test Agent Selection | HUMAN ACTION REQUIRED | Candidate not approved |
| Low-risk node selection | HUMAN ACTION REQUIRED | Batch candidates not approved |
| Staging Deployment | **NO-GO** | Multiple mandatory gates missing |
| Production | **NO-GO** | Staging and observation gates incomplete |

The authenticated Staging deployment must not be switched until every minimum gate
has passed. Code completion is not deployment authorization.
