# Phase 4 security threat model

## Protected assets

- Owner, administrator, operator, and viewer sessions;
- Agent identities, Controller signing material, CA material, and CRLs;
- inventory, metrics, alerts, incidents, approvals, audit records, and recovery metadata;
- notification and backup credential references;
- signed repair tasks and their results;
- off-site backups and restore attestations.

Secret values are never part of a public DTO. Settings expose only configured/not-configured state
and source metadata. The dashboard remains authenticated; the cancelled anonymous-read-only
experiment is not part of this branch.

## Trust boundaries

1. Browser to Web/Controller: HTTPS, authenticated session or Bearer token, CSRF for cookie-backed
   writes, TOTP where configured, login limiting, role and explicit-scope checks.
2. Agent to Gateway: TLS 1.3 mutual authentication, host-bound certificate identity, CRL
   enforcement, and no Controller custody of Agent private keys.
3. Gateway to Controller: private ingress with a separately protected trusted identity signal.
4. Controller to PostgreSQL: controlled connection material and schema migrations.
5. Controller to notification targets: restricted outbound webhook behavior, encrypted channel
   configuration, bounded retries, and dead-letter state.
6. Backup worker to off-site repository: file-backed credentials, fixed command arguments, verified
   upload, and isolated restore before a recovery point is considered verified.

## Authorization model

Roles are a ceiling:

| Role | Operational read | Routine operations | User administration | Owner changes |
| --- | --- | --- | --- | --- |
| Viewer | Yes | No | No | No |
| Operator | Yes | Bounded | No | No |
| Admin | Yes | Yes | Bounded | No last-Owner removal |
| Owner | Yes | Yes | Yes | Reauthentication required |

When a user has explicit scopes, those scopes are an additional restriction, not an expansion of
the role. Read and write are checked separately for operations, hosts, services, alerts, incidents,
repairs, approvals, recovery, audit, users, agents, notifications, and settings. Authorization is
enforced by the API even if the UI hides an action.

Session tokens carry a session-version claim. Disabling a user, rotating a password, or revoking
sessions increments the stored version and invalidates earlier sessions. The last active Owner
cannot be disabled or demoted.

## Principal threats and controls

| Threat | Control | Residual gate |
| --- | --- | --- |
| Anonymous or invalid-credential access | authenticated API dependency; no anonymous fallback | Staging 401 smoke test |
| CSRF against a logged-in browser | double-submit token on cookie-backed writes | browser regression test |
| Privilege escalation | role ceiling, explicit scopes, reauthentication, audit | full API permission matrix |
| Session theft after account change | session-version revocation | Staging session invalidation test |
| Agent impersonation | host-bound CSR, local private key, mTLS, SAN checks | live multi-Agent validation |
| Revoked Agent reconnect | Gateway CRL validation | fresh TLS-handshake rejection evidence |
| Replay of enrollment or tasks | single-use/TTL enrollment, nonce and signed task controls | concurrent Staging tests |
| Arbitrary remote execution | registered repair actions only, approvals by risk, signed tasks | no generic shell action |
| SSRF or DNS rebinding | URL and resolved-address validation | negative regression suite |
| Secret disclosure | protected files, encrypted fields, redacted DTOs/logging | Gitleaks and runtime log review |
| Notification amplification | channel scope/severity filters, bounded retries, dead letter | real two-channel exercise |
| Destructive restore | dry-run default, exact confirmation, approval, isolated validation | current restore exercise |
| Deployment drift | immutable commit metadata and production fail-closed settings | CI image/manifest provenance |

## Fail-closed production rule

`production_deployed=true` is accepted only when environment and deployment stage are both
`production`, the operations gate is exactly `approved_for_production`, and the deployment commit
is an immutable 40-character lowercase Git SHA. This is a guard, not production approval. The
human production authorization table and every operational gate must still pass.

## Explicit exclusions

Guardian automation must not alter SSH, firewall rules, system users, Xray, Sing-box, Shadowsocks,
Reality, subscriptions, DNS, Komari, or arbitrary files. It must not run unregistered scripts or an
arbitrary shell. Level 3 changes and database restoration remain approval-separated.

## Current decision

Code controls are testable locally, but Phase 3 Security remains **NO-GO** until the current
Gateway rejects a revoked certificate during the TLS handshake and CRL reload failure/concurrency
are revalidated. Production remains **NO-GO**.
