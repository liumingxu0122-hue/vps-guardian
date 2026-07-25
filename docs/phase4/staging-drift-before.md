# Phase 4 Staging drift before deployment

This is the sanitized, read-only baseline captured before the Phase 4 real Staging
deployment. It records only VPS Guardian scope and coexistence evidence needed for
rollback. It contains no passwords, tokens, private keys, private addresses, Agent
identities, user addresses, or unrelated application configuration.

## Evidence boundary

- Audit window: 2026-07-25 00:19-00:27 UTC.
- Target: the authenticated `panel.liuwave.com` **Staging** deployment.
- Candidate source: `108d7880e9f5f1b5455245be927ea7fb02d8346f`.
- Candidate branch: `feat/phase4-completion-ui-v2`.
- Candidate base: `origin/main` at
  `bd7cb236e6ecaf7c933d238f226d6a5d871674ed`.
- No production, DNS, Komari, proxy-node, subscription, firewall, SSH, or
  host-global runtime change was made.

During a version-probe, the Agent executable treated `version` as a run command
instead of a reporting command. The exact extra process was terminated immediately.
The managed Agent retained the same systemd main PID, remained active, and reported
`NRestarts=0`. No configuration, identity, or service change was observed. Because
the extra process used the existing test-host configuration, one duplicate
heartbeat or metric write cannot be excluded; the audit does not claim that probe
was data-read-only.

## Current runtime identity

All four project containers were running, healthy, and at restart count zero.
They do **not** share one immutable release identity.

| Component | Container ID | Configured image | Image ID / digest | Source evidence |
| --- | --- | --- | --- | --- |
| Controller | `cfd9442a5924` | `vps-guardian-staging/controller:v0.3.0-alpha.1` | `sha256:93268f2a15d608d140f7cf47ab0de33b464b2703e84abfd6fabc35dfec014803` | OCI label `3d493406135a6be1e9cd8d55392b5bd26e0845c7`; package `0.3.0a1` |
| Web | `9b5cbe852337` | `vps-guardian-staging/web:v0.3.0-alpha.1-route-bd7cb236` | `sha256:72aacf379ee7bd5df96cca4f5019a7dc407e16f50e9a1f82b1d849837034857b` | Tag and clean detached source tree point to `bd7cb236`; no VPS Guardian source label |
| Agent Gateway | `f5546f65a039` | digest-pinned HAProxy 3.4.2 | `sha256:0878b11eb64c433be1b0f578a584b8aca12f6caaa64c8f239b8b556c0dd5eeeb` | Third-party digest only; runtime HAProxy configuration is an external host file |
| Database | `deb5080b10cf` | `vps-guardian-staging/database:20260720T230401Z-d761d5305236` | `sha256:30791700eb3e6d93fcafbe7ac876ed3cbab1b6b863320b0f7a9a53dcb76aee02` | Image label `d761d530523627b02de3a27c0bde946c3ea35ca2`; release directory is not a Git worktree |

The host Agent is a systemd binary, not a container image. Its executable and
configuration have SHA-256 evidence, but the installed binary exposes no safe
version-reporting command and has no independently verifiable OCI revision. Its
source provenance is therefore **not proven** by the current deployment.

## Compose and configuration stack

The Compose project is `vps-guardian-staging`. Its effective runtime is assembled
from a clean detached source tree plus host-managed overlays:

1. `/srv/vps-guardian-staging/sources/routefix-bd7cb236/docker-compose.yml`
2. `/etc/vps-guardian-staging/phase4c.compose.yml`
3. `/etc/vps-guardian-staging/routefix-bd7cb236.compose.yml`
4. `/etc/vps-guardian-staging/panel-domain-controller.compose.yml`
5. `/etc/vps-guardian-staging/rollback-anonymous-readonly.compose.yml`
6. `/etc/vps-guardian-staging/agent-gateway-host-header.compose.yml`
7. files from the older `d761d530` release directory

Container labels show that the exact overlay list differs between services because
individual components were recreated at different times. The source tree is clean
at `bd7cb236`, but the effective release cannot be reproduced from that Git commit
alone.

Host-managed files outside Git include:

- all `/etc/vps-guardian-staging/*.compose.yml` overlays;
- the HAProxy host-header/mTLS configuration;
- the root-owned Compose environment file;
- the aaPanel-managed Nginx virtual host and proxy include;
- TLS, Agent CA, signing, database, JWT, encryption, enrollment, proxy-auth, and
  Restic secret files referenced below;
- the older extracted database release directory.

The server also retains an inactive `anonymous-readonly.compose.yml` experiment.
The active Controller was recreated with
`rollback-anonymous-readonly.compose.yml`, which explicitly disables anonymous
mode. Management APIs returned `401` without credentials. The cancelled anonymous
overlay must not be included in the Phase 4 RC stack.

## Schema and data state

- Alembic revision: `0007_multivps_alerts`.
- Candidate migration: `0008_phase4_completion`.
- The existing `users` table has no `scopes`, `session_version`,
  `last_login_at`, or `disabled_at` columns.
- Users: 2 total; 1 active Owner and 1 disabled Operator.
- Recovery Owner: **absent**.
- TOTP-enabled users: 0.
- Hosts: 13.
- Enrolled Agents: 2.
- Agent identities: 2 active, 1 retiring, 3 retired, and 5 revoked.
- Service checks: 8.
- Metric samples: 16,279, from 2026-07-21 11:29:42 UTC through
  2026-07-25 00:24:53 UTC.
- Service-check results: 49,276, from 2026-07-22 20:26:25 UTC through
  2026-07-25 00:24:53 UTC.
- Enabled hosts fresh in the five-minute window: 2.
- Alerts: 10; incidents: 19; approvals: 7.
- Notification channels: 1; delivery records: 6. No two-channel external
  closure is proven.
- Application Recovery Point rows: 0.

The absence of a second active Owner is a deployment blocker under the Staging
runbook. The known Owner password is represented by a root-owned secret file and is
considered exposed. Its contents were not read. Rotation, session-version
increment, and old-session rejection cannot be claimed until the candidate schema
is active and a human receives the replacement through a secure channel.

## Browser, Controller, and reverse proxy

- Public `/health`: `200`.
- Public SPA routes `/overview`, `/security`, `/users`, `/agents`,
  `/notifications`, and `/settings`: `200`.
- Unauthenticated `/api/v1/auth/me`, `/api/v1/overview`,
  `/api/v1/hosts`, and `/api/v1/audit`: `401`.
- Web Caddy configuration validation: passed.
- The Web listener is bound to loopback only; public TLS terminates at host Nginx.
- The Agent Gateway remains a separate public listener and only the bootstrap path
  can omit a client certificate.
- Nginx syntax validation: passed.
- Nginx is managed by the host panel and owns ports 80/443, while
  `systemctl is-active nginx` reports inactive. This service-manager mismatch must
  be preserved and investigated, not repaired during Guardian deployment.
- The Nginx site proxies only the Guardian public host to the loopback Web
  listener. Its configuration and certificate references are outside Git and have
  baseline hashes for the backup manifest.

## Secret references

Secret contents were not read or printed. The effective stack references
root-controlled files below `/etc/vps-guardian-staging/secrets` for:

- PostgreSQL password and database URL;
- JWT and field-encryption keys;
- enrollment token and Gateway proxy authentication;
- Controller signing key;
- Agent CA certificate/private key and Gateway CRL material;
- Gateway and browser TLS certificate/private key;
- Restic password;
- dedicated Phase 4C fixture credentials;
- the current Staging Owner credential.

The Controller receives secrets as read-only bind mounts under `/run/secrets`.
The Gateway receives its TLS/CA/CRL directory read-only. The pre-deployment backup
must record only paths, metadata, and SHA-256 values in evidence; secret values
must remain excluded.

## Networks, volumes, systemd, and scheduled work

Guardian networks:

- `vps-guardian-staging_backend`;
- `vps-guardian-staging_agent_ingress` (internal);
- `vps-guardian-staging_agent_edge`.

Guardian volumes:

- PostgreSQL data;
- Controller data;
- recovery exchange;
- backup state and cache;
- Caddy data and configuration.

The four application containers are isolated from unrelated Compose projects.
Docker data is already on the mounted secondary filesystem. Root usage was 37%;
the secondary filesystem was 61%. No runtime-data migration is authorized.

Guardian systemd units present and active:

- the host Agent;
- the dedicated Phase 4C synthetic fixture.

The Komari Agent and Komari-side panel service were active and were not inspected
for credentials or changed. No Guardian/Restic backup timer or cron entry was
active. The snapshot of all non-Guardian container identities/statuses, Docker
networks, Docker volumes, and running systemd units was reduced to SHA-256 baseline
hashes for later before/after comparison.

## Backup and restore drift

- Compose declares `RESTIC_REPOSITORY` and a local backend.
- The Restic repository is inside the Guardian Docker backup-state volume on the
  same controller host.
- Host-level off-site Restic repository and object-storage credential files are
  absent.
- The host Restic client cannot read the volume repository because the repository
  format is newer than that client.
- The configured container-visible repository path does not exist at the same path
  in the host mount namespace; validation must use the matching candidate backup
  image or a version-compatible client.
- No current off-site snapshot, isolated cross-cloud restore, or independent
  restore credential is proven.
- Previous RPO/RTO values in the old Phase 4C overlay are historical configuration
  metadata, not current measured evidence.

This is a hard deployment blocker: a same-host local repository cannot satisfy the
required off-site recovery gate.

## Resource sample

| Service | CPU | Memory |
| --- | ---: | ---: |
| Controller | 0.40% | 96.07 MiB |
| Web | 0.76% | 22.09 MiB |
| Agent Gateway | 4.99% | 27.42 MiB |
| PostgreSQL | 0.03% | 222.4 MiB |
| Komari server (comparison only) | 0.81% | 44.54 MiB |

This single sample is a coexistence baseline, not a capacity conclusion.

## Drift conclusion and pre-deployment gate

| Gate | Result | Reason |
| --- | --- | --- |
| Fixed candidate commit | GO | `108d788` is clean, pushed, and reviewed by green CI |
| Current runtime health | GO | Four Guardian containers healthy, restart count zero |
| Authentication boundary | GO | Management APIs reject anonymous access |
| Reproducible current release | NO-GO | Four components do not share a release; host overlays are outside Git |
| Migration provenance | GO with test required | Current `0007`; candidate `0008`; up/down/up still required in a disposable database |
| Rollback images | GO for current four components | Current image IDs remain locally addressable; preservation must be rechecked before deployment |
| Recovery Owner and TOTP | **NO-GO** | Only one active Owner and no TOTP-enabled user |
| Off-site Restic restore point | **NO-GO** | Only a same-host local repository is configured |
| Real external notifications | NO-GO | Two independently configured external channels are absent |
| Agent immutable provenance | NO-GO | Installed host binary has only a binary hash, not a verifiable release identity |
| Production | **NO-GO** | Staging acceptance and long observation are incomplete |

No Staging deployment may begin until the recovery-Owner and off-site-backup
blockers are resolved. Local candidate build and disposable-environment validation
may proceed without changing the server. The production conclusion remains
**NO-GO**.
