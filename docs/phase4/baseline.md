# Phase 4 baseline

This document freezes the evidence collected before the Phase 4 Completion Sprint. It is
deliberately free of credentials, private host identifiers, addresses, and customer data.
Historical claims are not treated as current measurements.

## Evidence boundary

- Audit time: 2026-07-24 21:58–22:08 UTC.
- Repository remote: the public VPS Guardian repository.
- Starting point: `origin/main` at `bd7cb236e6ecaf7c933d238f226d6a5d871674ed`.
- Public prerelease: `v0.3.0-alpha.1`.
- Sprint branch: `feat/phase4-completion-ui-v2`, created directly from that `origin/main`.
- The cancelled anonymous-read-only branch is not an ancestor of the sprint branch.
- The original working tree remains unchanged. Its five anonymous-read-only experiment files
  have an external binary patch, file copies, and a verified SHA-256 manifest.

## Deployment baseline

The public dashboard hostname points to the **staging** deployment and requires authentication.
An unauthenticated request to the protected Overview API returned `401` after the access-control
rollback was verified.

The four Guardian containers were healthy with zero observed restart loops:

| Component | Runtime version or image | Source evidence |
| --- | --- | --- |
| Controller | `0.3.0a1` | Image label points to `3d493406`; Compose working tree points to `bd7cb236` |
| Web | Caddy `2.11.4` with the route-fix Web image | Compose working tree points to `bd7cb236` |
| Agent Gateway | HAProxy `3.4.2` | Staging Compose overlays |
| Database | PostgreSQL `17.10` | Older release source `d761d530` |

This is a real deployment drift: Controller, Web, and Database do not share one immutable release
identity. Phase 4 deployment must converge them to one reviewed commit and preserve rollback.

The Controller host runs Ubuntu 22.04 with synchronized time. Host Nginx terminates public TLS,
proxies the browser endpoint to a loopback-only Web listener, and verifies the upstream certificate.
The Agent Gateway remains a separate listener and trust boundary.

## Fleet baseline

Guardian database counts at the audit time:

| Item | Current value |
| --- | ---: |
| Inventory rows | 13 |
| Enabled rows | 12 |
| Disabled rows | 1 |
| Fresh enabled hosts (5-minute window) | 2 |
| Stale enabled hosts | 10 |
| Enrolled Agents | 2 |
| Active non-revoked Agents (5-minute window) | 2 |
| Pending enrollment tokens | 0 |
| Service checks | 8 enabled of 8 |
| Active alerts | 0 |
| Non-resolved incidents | 4 |
| Pending approvals | 0 |

Both active Agents reported version `0.3.0-alpha.1`. Identity rows included active, retiring,
retired, and revoked generations; lifecycle correctness must therefore be checked, not inferred
from the active-Agent count.

Komari remains parallel and untouched. It held 13 client rows and 9 clients with data in the same
five-minute window. Guardian and Komari disagree because Guardian has only two enrolled Agents.
No replacement or bulk rollout is justified by this baseline.

## Data and observation baseline

- Metric samples: 15,993 rows from 2026-07-21 09:04 UTC through 2026-07-24 21:59 UTC.
- Service-check results: 46,988 rows from 2026-07-22 20:26 UTC through 2026-07-24 21:59 UTC.
- The metric range exceeds 24 hours but does not establish seven continuous days.
- Sampling continuity and gaps still require an explicit observation-run calculation.
- The database contained no application-level Recovery Point records.
- No notification channel was enabled and there were no delivery rows proving an external
  notification loop.

## Security baseline

The code baseline contains TLS 1.3 mTLS, host-bound one-time CSR bootstrap, Agent-local private
keys, monotonic CRL publication, signed tasks, nonce replay protection, RBAC, TOTP, CSRF,
login limiting, approvals, append-only audit records, SSRF controls, DNS-result validation, and
restricted Secret-file loading.

Operational evidence confirmed:

- dashboard authentication is enforced;
- two active Agent identities and multiple retired/revoked lifecycle rows exist;
- Agent and gateway services are running;
- runtime Secret files are mounted read-only and their source files are root-only.

Operational evidence still required:

- a fresh TLS-handshake rejection test for a revoked certificate;
- CRL unreadable/fail-closed and concurrent reload tests;
- a complete certificate rotation without an unintended dual-active window;
- a fresh isolated restore and current RPO/RTO measurement;
- Owner credential rotation and old-session invalidation.

The historical Phase 3E `RPO ≈ 16s` and `RTO ≈ 50s` remain an **accepted historical snapshot**,
not a current result.

## Storage and performance baseline

The historical unmounted-disk concern is no longer current:

- root filesystem: 49 GiB total, 37% used;
- second 50 GiB filesystem: mounted at the runtime-data mount;
- Docker root: on the second filesystem;
- containerd: active, with its current root subject to the final migration runbook review;
- no immediate runtime-data migration is justified.

One no-stream sample recorded:

| Component | CPU | Resident memory |
| --- | ---: | ---: |
| Controller | 0.67% | 84.2 MiB |
| Web | 0.93% | 21.23 MiB |
| Agent Gateway | 0.78% | 27.52 MiB |
| PostgreSQL | 0.00% | 227.9 MiB |
| Komari server | 0.31–0.74% | 44.8–45.1 MiB |

The current Web production build produced:

- shared entry: 232.99 kB raw / 85.42 kB gzip;
- CSS: 46.81 kB raw / 9.57 kB gzip;
- Overview route: 19.12 kB raw / 6.02 kB gzip.

API P50/P95 and browser first-content measurements still require a controlled authenticated run.

## Baseline gates

- Ruff: passed.
- Mypy strict: passed for 33 source files.
- Pytest: 268 passed, 17 skipped after moving temporary files to a writable workspace directory.
- Web typecheck: passed.
- Web unit tests: 17 passed.
- Web production build: passed.
- npm audit at install time: 0 vulnerabilities.
- Go, Docker image builds, Gitleaks, SBOM, image scans, and Linux lifecycle tests require CI or a
  Linux runner; the Windows workstation does not claim those gates.

## Initial conclusion

- Phase 3 Security: **PENDING revalidation**.
- Phase 3 DR: **PENDING revalidation**.
- Phase 4 Code: **NO-GO** at baseline.
- Phase 4 Feature: **NO-GO** at baseline.
- Phase 4 UI: **NO-GO** at baseline.
- Phase 4 Staging: **NO-GO** at baseline.
- Phase 4 Observation: **PENDING**.
- Production: **NO-GO**.
