# Identity recovery lifecycle

This candidate patch is code-only. It has not been deployed, no online database has
been migrated, and no live user, password, TOTP secret, recovery code, or session has
been changed.

## Security boundaries

- An authenticated Owner is the only identity that can create another Owner. The
  bootstrap CLI can create only the first identity in an empty database.
- Owner-created identities receive an initial Argon2id-hashed password and
  `must_change_password=true`. The server permits only password change, TOTP setup,
  TOTP confirmation, recovery-code confirmation, and logout until onboarding ends.
- TOTP secrets are encrypted with the configured Fernet key. Setup secrets and
  recovery codes are returned once and are never written to audit records.
- Recovery codes use cryptographically secure randomness. Only keyed SHA-256 digests
  are stored. Consumption is locked, single-use, and batch regeneration revokes every
  older unused code.
- Every JWT contains a server-side session identifier and user session version. Every
  authenticated request loads the current user and session row, then checks account
  state, role, scopes, session version, revocation, and expiry.
- Password changes increment the session version, revoke all other sessions, and
  reissue the explicitly retained current session. Role, scope, disable, TOTP-disable,
  and administrative password changes revoke affected sessions.
- Last-Owner mutations lock active Owner rows. Delete, disable, demotion, and
  all-session revocation are rejected and audited when they would remove the last
  usable Owner boundary.
- Session IP and user-agent values are keyed digests. Audit details exclude passwords,
  password hashes, TOTP secrets, recovery codes, JWTs, cookies, and CSRF tokens.

## Threat model

| Threat | Server control | Residual risk |
| --- | --- | --- |
| Stolen JWT | Server session row, expiry, revocation, session version | Valid token remains usable until detected or expired |
| Initial-password abuse | Forced setup allowlist enforced on every request | Initial password delivery remains an operational responsibility |
| TOTP replay | Monotonic accepted time-step counter | Concurrent use across multiple Controller replicas needs serialized database access |
| Recovery-code database disclosure | Keyed digest only; one-time consumption | JWT secret compromise permits offline verification attempts |
| Last-Owner race | `SELECT ... FOR UPDATE` around active Owners | SQLite is test-only and does not provide PostgreSQL row-lock semantics |
| Secret leakage | Explicit response DTOs and redacted append-only audit | Browser memory and clipboard remain endpoint risks |

## Migration and rollback request

Migration `0010_identity_recovery` is reversible and follows
`0009_agent_provenance`. Before any future Staging authorization:

1. take an encrypted database backup and record its SHA-256;
2. restore it to an isolated PostgreSQL copy;
3. record table row counts and identity/audit integrity checks;
4. run `alembic upgrade 0010_identity_recovery`;
5. validate users, audit rows, recovery-code hashes, and session consistency;
6. run `alembic downgrade 0009_agent_provenance`, validate compatibility, then
   upgrade again;
7. request a separate change window and rollback approval.

Do not run these steps against the current online Controller without explicit
authorization. Staging deployment is `NO-GO`; Production is `NO-GO`.
