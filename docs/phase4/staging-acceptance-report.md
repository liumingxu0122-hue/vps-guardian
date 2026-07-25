# Phase 4 Staging acceptance report

This report records the 2026-07-25 Phase 4 RC build, disposable-environment
validation, pre-deployment backup, and deployment gate decision. It is intentionally
sanitized. It contains no password, token, private key, private address, Agent
identity, user address, or unrelated application configuration.

The real Staging deployment was **not** performed. Mandatory preconditions failed
before the change window: there is no independent recovery Owner, no TOTP-enabled
Owner, and no off-site Restic repository or credential set. Candidate work stopped
before any active container, schema, public route, Agent, Komari service, DNS, or
proxy-node change.

## 1. Actual commit, version, tag, and image identities

- Candidate source:
  `108d7880e9f5f1b5455245be927ea7fb02d8346f`.
- RC version: `0.4.0-phase4-rc1`.
- RC tag suffix: `v0.4.0-phase4-rc1-108d788`.
- Controller and Backup image:
  `sha256:39e46bc806242dd27fcc7a9383dea09af92b6ea1461283da9ef8911f6ee797ff`.
- Web image:
  `sha256:2aed71e7a6e81e98f1b1ceb2d8ffd3df8fa76b4b072f9115cf3caf765f6bc03a`.
- Database image:
  `sha256:4d55b96897dcd008bbe416e7ce6d55f691a2911221bd03e69e86c49713f0707b`.
- Build time label: `2026-07-25T00:39:28Z`.
- Each RC image has OCI version, full revision, creation time, source, license, and
  a real SBOM artifact reference from successful CI run
  [30134578676](https://github.com/liumingxu0122-hue/vps-guardian/actions/runs/30134578676).
- No `latest`, floating, unrevisioned, or temporary RC image tag was created.
- The Agent has no OCI Dockerfile in this architecture. A fixed-source Linux
  binary was built and tested, with SHA-256
  `b9b8037227baf58d141216a6eb690a189343e359d66ba0cbc108196edb3122a0`.
  The source has no embedded version command or version variable. Agent immutable
  image/version provenance is therefore a gate failure, not an inferred pass.

## 2. Deployment time, downtime, and service interruption

- Real Staging deployment start: not started.
- Real Staging deployment end: not started.
- Public Staging downtime caused by this activity: 0 seconds observed.
- Real Staging schema outage: none.
- Temporary validation projects used separate networks, volumes, ports, and
  Secrets. Both were removed after evidence capture.

## 3. Container health and restart count

After build and temporary validation, the existing Staging Controller, Web, Agent
Gateway, and PostgreSQL containers remained running and healthy with restart count
zero. Their pre-existing image IDs did not change.

The disposable candidate Controller, Web, and PostgreSQL containers reached
healthy state during validation. They were not promoted to the real project.

## 4. Database migration result

Migration `0008_phase4_completion` passed:

1. empty PostgreSQL: base through `0008`;
2. downgrade from `0008` to `0007_multivps_alerts`;
3. second upgrade to `0008`;
4. a separate restore of the real pre-deployment Staging dump at `0007`;
5. real-data-copy upgrade, downgrade, and second upgrade;
6. all 14 key-table row counts were identical before and after the real-data-copy
   migration cycle;
7. both existing users received `session_version=1`.

The online dump contained four fewer service-check results than the count recorded
after the dump completed. Every other recorded table count matched. This is the
expected boundary of a consistent online snapshot while the live system continued
collecting results; it is not a restore loss.

The active Staging database remains at `0007_multivps_alerts`.

## 5. User, RBAC, and credential result

Disposable-environment checks passed:

- Owner login: `200`;
- invalid credential: `401`;
- authenticated Owner profile and user list: `200`;
- Viewer read: `200`;
- Viewer write attempt: `403`;
- logout: `204`;
- request after logout without a session: `401`;
- production-deployed flag with a Staging stage: fail-closed as required.

Real Staging has only one active Owner, one disabled Operator, and no TOTP-enabled
user. No recovery Owner was created. The known Owner credential was not read,
printed, copied into Git, or rotated.

## 6. UI page result

The candidate Web image served the SPA shell successfully for all 16 required
routes in the isolated network:

- Overview;
- Attention;
- Hosts;
- Services;
- Topology;
- Alerts;
- Incidents;
- Repairs;
- Approvals;
- Recovery;
- Security;
- Users;
- Agents;
- Notifications;
- Audit;
- Settings.

Static index and API proxy behavior passed. Candidate API requests without a
credential returned `401`; invalid credentials did not fall back to any anonymous
mode.

Real-browser validation at 1440, 1920, 1366, 768, and 390 pixels, light/dark mode,
keyboard navigation, real loading/empty/error states, and sanitized real Staging
screenshots remain pending because the RC was not deployed.

## 7. Phase 3 security regression

The fixed commit's CI security and Agent test suites passed. No real Phase 3
certificate-lifecycle fault injection was performed in this run.

The existing two Agents were not assumed to be disposable. Without an explicitly
identified dedicated test Agent, the run did not revoke certificates, replace a
CRL, test an unknown CA, replay a CSR against the real Gateway, rotate a real
identity, or change an Agent private key. No business node was used for fault
injection.

Result: real Phase 3 security acceptance is **pending**.

## 8. Disaster recovery result

Pre-deployment evidence:

- PostgreSQL custom dump size: 125,566,165 bytes;
- schema-only dump: created;
- migration revision and 14 key-table counts: captured;
- `pg_restore -l`: 201 lines and readable;
- configuration, environment-key, Secret path/hash, Nginx, systemd, timer, cron,
  container, image, volume, network, source, health, and coexistence evidence:
  captured;
- evidence-file count at initial manifest: 41;
- backup manifest SHA-256:
  `302225211fd8be953b49fd845576a599f1fee51cbbdf6c05e1a86ed1357774df`;
- all manifest entries: verified;
- all four old image IDs: locally available.

A same-host Restic snapshot was created:

- snapshot:
  `faa545acdcdf570c379f8166a62a2ee04490add2faf02487d8ad7ec8e82c1759`;
- tags: `phase4-predeploy`, `108d788`;
- Restic `check --read-data`: all snapshots, trees, blobs, and packs passed;
- isolated same-host file restore: passed;
- restored internal manifest: 39 entries passed;
- restored PostgreSQL dump directory: 201 entries and readable.

The first local snapshot attempt failed before snapshot creation because its
one-time container had only 16 MiB of temporary space. No prune or forget was run;
the successful retry used 512 MiB and the subsequent full check found no errors.

This is **not** an off-site or cross-cloud restore. The repository is on the same
controller filesystem, host-level off-site Restic credentials are absent, and no
isolated PostgreSQL application stack was authenticated from a remote recovery
location. Real RPO and RTO were not measured.

Result: local recovery evidence GO; disaster-recovery gate **NO-GO**.

## 9. Notification closure

No real Telegram, email, or Discord credential was available through a protected
injection path. No external event, retry, or dead-letter test was performed.
Existing Staging records do not prove two independent real channels.

Result: **pending / NO-GO**.

## 10. Multi-VPS rollout

- Existing enrolled Agents: 2.
- No existing Agent was upgraded or reconfigured.
- No low-risk node list was supplied.
- No enrollment token was created.
- No batch-2 or batch-3 node was touched.
- No bulk action was executed.

Result: existing two-node state preserved; Phase 4C batch expansion **pending**.

## 11. Komari comparison

Komari remained active throughout. Its server and Agent service both reported
active with restart count zero after candidate build and temporary validation.
No Komari configuration, token, Agent, database, route, container, or DNS record
was changed.

The pre-change comparison sample was 0.81% CPU and 44.54 MiB for the Komari server.
No seven-day comparative conclusion is claimed.

## 12. Real rollback drill

A root-protected rollback evidence bundle was created with:

- the previous database dump and schema;
- current exact image IDs;
- an image-ID-pinned rollback Compose override;
- the current authenticated Staging overlay order;
- migration revision `0007_multivps_alerts`;
- component-by-component rollback guidance;
- Nginx and coexistence baselines.

No real application rollback was run because no real RC deployment occurred.
Running a rollback without first deploying the RC would only create avoidable
Staging risk.

Result: rollback assets GO; real rollback/redeploy exercise **pending**.

## 13. Owner password rotation

Not performed.

There is only one active Owner, no recovery Owner, no TOTP-enabled Owner, and no
approved secure delivery path for a replacement password. The hard rule requires
stopping at this manual step. No password appears in Git, build logs, screenshots,
or this report.

Before deployment, a human must:

1. create and verify an independent recovery Owner;
2. enable and verify TOTP;
3. receive the replacement credential outside chat, argv, logs, and Git;
4. rotate the exposed Owner credential;
5. increment `session_version`;
6. verify old sessions return `401`;
7. verify the new login and audit event.

## 14. Resource overhead

Pre-change sample:

| Service | CPU | Memory |
| --- | ---: | ---: |
| Controller | 0.40% | 96.07 MiB |
| Web | 0.76% | 22.09 MiB |
| Agent Gateway | 4.99% | 27.42 MiB |
| PostgreSQL | 0.03% | 222.4 MiB |
| Komari server | 0.81% | 44.54 MiB |

The candidate was not left running, so no real Staging before/after overhead is
claimed. Docker-data filesystem utilization increased from 62% to 70% because RC
images, build cache, backup evidence, and restore evidence were intentionally
retained. No image or build-cache prune was performed.

## 15. Screenshot evidence

No real Staging after-screenshot was captured because there was no RC deployment.
No screenshot containing an address, user address, token, private key, Agent
identity, or unrelated application was produced.

Result: real screenshot evidence **pending**.

## 16. Logs, restart count, and anomalies

- Existing four Guardian containers: healthy, restart count zero.
- Candidate temporary containers: healthy before controlled removal.
- Build logs and validation logs: preserved in the root-protected build record.
- Build-record manifest SHA-256:
  `cd959aa8020fc1a5c6c66968a3056b6d625cbd49b7e3a370a7677c0b937e85ef`.
- Validation manifest SHA-256:
  `89800cdcfe0c593b4c1ea8ea85f09514117f7fd531640550b02c49373a6ae1c8`.

Recorded expected validation corrections:

- a 16 MiB Restic temporary filesystem was too small; retry and full data check
  passed;
- a temporary script/Caddyfile initially had an unreadable mode for its
  non-root container user; test-only permissions were corrected;
- the first temporary Caddy route let SPA fallback answer an API path; the
  Controller itself returned `401`, the temporary route was replaced with the
  repository's named-matcher structure, and the full suite passed;
- a host Agent `version` probe was interpreted as a normal Agent launch. The exact
  extra process was terminated; the managed Agent retained its PID, active state,
  and restart count zero. One duplicate heartbeat or metric write cannot be
  excluded.

## 17. Alert noise and false-positive conclusion

Not enough real RC runtime data exists. Alert noise, false positives, and
notification noise were not re-measured.

Result: **pending**.

## 18. Status history and audit conclusion

The existing database had 330 audit rows at backup time. Candidate temporary
authentication and RBAC tests used only the disposable database. No real Staging
incident status, alert assignment, repair, approval, notification, or user audit
row was intentionally created.

Historical status visibility is implemented and covered by the fixed commit's
automated tests, but real Staging operational acceptance remains pending.

## 19. Security-boundary conclusion

Passed without changing real Staging:

- real unauthenticated management API: `401`;
- candidate unauthenticated management API: `401`;
- candidate invalid credential: `401`;
- candidate Viewer write: `403`;
- candidate production-deployed flag outside production stage: rejected;
- secret values excluded from Git and reports;
- temporary validation Secrets destroyed after their hashes were recorded;
- public browser, Agent mTLS, database, and backup boundaries remained separate;
- no arbitrary shell repair, bulk fleet action, DNS change, Komari change, or
  proxy-node change.

Not passed:

- independent recovery Owner and TOTP;
- Owner credential rotation and session invalidation;
- real CRL/unknown-CA/rotation/replay tests;
- off-site backup and isolated application recovery;
- two real external notification channels;
- Agent immutable version provenance.

## 20. Constraint deviations

No production deployment, `main` merge, DNS switch, public anonymous panel, Komari
change, proxy-node change, bulk VPS action, or real schema migration occurred.

One audit command deviated from the intended read-only boundary: the Agent binary
does not implement a version subcommand and started an extra process. The exact
process was terminated immediately after discovery. It did not replace or restart
the managed service, but one duplicate heartbeat or metric write cannot be ruled
out. This report does not hide or reclassify that event as read-only.

## 21. Remaining risks and blockers

1. No recovery Owner.
2. No TOTP-enabled Owner.
3. Exposed Owner password not rotated.
4. No secure replacement-password delivery path.
5. No off-site Restic backend or credentials.
6. No cross-cloud isolated PostgreSQL/application restore.
7. No measured current RPO/RTO.
8. No two-channel real notification closure.
9. No dedicated real certificate-lifecycle test Agent identified.
10. No Agent OCI image or embedded version provenance.
11. Effective live Staging still depends on host-managed overlays outside Git.
12. Nginx runs under host-panel management while the conventional systemd unit is
    inactive.
13. No real browser/device screenshot matrix for the deployed RC.
14. No real rollback and redeploy drill.
15. No 24-hour or seven-day RC observation.

## 22. Gate rollup

| Gate | Decision | Evidence |
| --- | --- | --- |
| Fixed source and CI | GO | Exact commit, successful CI, SBOM artifacts |
| RC Controller/Web/Database build | GO | Immutable tag, exact image IDs, OCI labels, no-network smoke |
| Agent build | PARTIAL | Binary test/build and hash pass; image/version provenance absent |
| Empty-database migration | GO | up/down/up passed |
| Restored real-data-copy migration | GO | up/down/up and key counts passed |
| Disposable login/RBAC/API/deep links | GO | Owner/Viewer/logout/401/403 and 16 routes passed |
| Current Staging health preservation | GO | Old deployment stayed healthy, restart count zero |
| Pre-deployment database/config backup | GO | Readable dump, schema, manifest, old images |
| Same-host Restic snapshot/check/restore | GO | Snapshot, full read-data check, isolated file restore |
| Off-site disaster recovery | **NO-GO** | No remote repository/credentials/application restore |
| Owner recovery/TOTP/rotation | **NO-GO** | One active Owner, no TOTP, no secure delivery |
| Real Phase 3 security | NO-GO | Dedicated test Agent not identified |
| Real notification closure | NO-GO | Protected channel credentials absent |
| Real Staging UI/browser acceptance | NO-GO | RC not deployed |
| Real multi-node expansion | NO-GO | Low-risk nodes not approved |
| Real rollback/redeploy | NO-GO | RC not deployed |
| 24-hour observation | Pending | Not started |
| Seven-day observation | Pending | Not started |
| Production | **NO-GO** | Mandatory Staging and observation gates incomplete |

## 23. Observation status

No observation job was started because there is no deployed RC to observe. A
24-hour or seven-day timer against the old deployment would not validate this
candidate and would create misleading evidence.

First checkpoint, 24-hour result, and seven-day result are all pending.

## 24. Merge and production recommendation

- Do not merge `main` yet.
- Do not deploy production.
- Do not switch the existing panel.
- Do not remove authentication.
- Keep the RC images, backup evidence, fixed source archive, and branch as
  Staging preparation evidence.
- Resume only after the recovery-Owner/TOTP, secure credential delivery, and
  off-site Restic blockers are resolved.
- After those blockers, deploy one component at a time, run the full real
  Staging/Phase 3/notification/multi-node/rollback matrix, and start the 24-hour
  and seven-day observation windows.

Final production decision: **NO-GO**.
