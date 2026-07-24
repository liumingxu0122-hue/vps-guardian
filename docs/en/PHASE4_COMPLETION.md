# Phase 4 completion guide

Phase 4 turns the Developer Preview into a more complete operations control plane while preserving
its authenticated dashboard, Agent trust boundary, constrained repair model, disaster-recovery
checks, and lightweight architecture.

## What this branch adds

- a decision-oriented Overview, a dedicated Attention queue, grouped responsive navigation,
  breadcrumbs, command palette, light/dark themes, and English/Simplified Chinese resources;
- version/commit/deployment provenance and deterministic health reasons;
- 1h/24h/7d/30d stability components with confidence, group, and location aggregates;
- persistent alert assignment/closure and audited incident state transitions;
- notification scope/severity filters, delivery history, bounded retry, and dead letter;
- Owner/Admin/Operator/Viewer management, explicit narrowing scopes, password rotation, session
  revocation, last-Owner protection, and reauthentication for high-risk Owner changes;
- bounded service-check history, structured approval details, Agent/security/notification/settings
  pages, pagination, request cancellation hooks, and GET request deduplication;
- reversible schema migration `0008_phase4_completion`;
- production configuration that fails closed without an explicit gate and immutable commit.

These are code capabilities, not proof that every Staging or production gate passed.

## Architecture and trust

Browser traffic reaches the authenticated Web/Controller endpoint. Agent traffic uses a separate
TLS 1.3 mTLS Gateway. Agent private keys stay on the Agent; the Controller issues certificates from
host-bound CSRs. Signed tasks, nonce replay defense, allowlisted repair actions, risk-based
approval, and append-only audit records keep remote actions bounded.

PostgreSQL stores operational state. Backup jobs use protected file-backed credentials and an
off-site Restic repository; a recovery point is not verified until an isolated restore and
application validation succeed.

See [Architecture](ARCHITECTURE.md), [Security model](SECURITY_MODEL.md), the
[Phase 4 threat model](../phase4/security-threat-model.md), and
[Backup/restore](BACKUP_AND_RESTORE.md).

## RBAC

- Viewer: read operations only.
- Operator: routine bounded operations; cannot administer privileged users.
- Admin: administration below Owner; cannot remove the last Owner.
- Owner: full role ceiling; high-risk account changes require the current password.
- Explicit scopes: optional additional restrictions such as `alerts:read`; they never grant more
  than the role and read/write are separate.

Cookie-backed writes require CSRF. Bearer tokens are authenticated but do not use cookie CSRF.
Disabling an account, rotating a password, or revoking sessions invalidates older session versions.

## Agent and certificate lifecycle

1. Create/select a host.
2. Issue a short-lived, single-use, host-bound enrollment token.
3. Agent generates its private key locally and submits a CSR.
4. Controller validates identity and signs a client-only certificate.
5. Gateway verifies CA, SAN/identity, validity, and CRL at the TLS boundary.
6. Renewal uses proof of the active identity and an atomic generation switch.
7. Revocation publishes a monotonic CRL and retires the old identity.

No permanent private key is displayed or sent to the Controller. Reinstallation must not silently
replace an existing identity. Live CRL handshake and rotation evidence remains a Phase 3 gate.

See [Agent installation](AGENT_INSTALLATION.md) and [Phase 4C](PHASE4C.md).

## Alert, incident, repair, and approval closure

Alerts move through Firing, Acknowledged, Silenced, Recovered, and Closed, with owner and
notification context. Incidents use:

```text
Open → Acknowledged → Investigating → Mitigating → Resolved
```

Every transition is audited. Resolution can include a summary and postmortem.

Repair remains:

```text
Request → Risk evaluation → Dry run → Approval → Execute → Verify → Roll back → Audit
```

Only registered actions are allowed: restart a specified service/container/Agent, clear a
predefined cache, rotate predefined logs, run a predefined health/Restic check, or safely
re-collect data. Arbitrary shell, SSH/firewall/user/proxy configuration, subscriptions, and
arbitrary deletion are outside the product boundary.

## Notifications

Telegram, email, Discord, and webhook channels have event-scope, severity, retry, and Secret
reference metadata. Delivery becomes success or dead letter after bounded attempts. Failures appear
in Overview/Attention. Passing requires real events through two external channels; a test message
does not pass that operational gate.

## Staging, rollback, storage, and Komari

Use the [Staging/rollback runbook](../operations/phase4-staging-runbook.md). Staging remains
authenticated. Komari stays installed and unchanged while selected Guardian Agents are observed in
batches. Current disk evidence does not justify a runtime-data migration.

## Observation and production

Follow the [observation run](../phase4/observation-run.md), the
[stability formula](../phase4/stability-score.md), and the
[production gate](../phase4/production-gate.md). The available baseline does not prove seven
continuous days. Production is **NO-GO**.
