# Identity recovery lifecycle

RC6 replaces browser JWT persistence with an opaque server-side session. This
candidate remains code-only until the separately authorized Staging gate succeeds;
Production remains `NO-GO`.

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
- Browser cookies contain a 384-bit opaque secret. The database stores only its
  SHA-256 hash, an independently bound CSRF-secret hash, privacy-safe device/IP
  summaries, idle expiry, absolute expiry, last activity, session version, and
  revocation state. API Bearer JWT remains a separate non-browser path.
- Standard browser sessions use a 12-hour idle and 7-day absolute lifetime.
  “Keep me signed in” uses a 7-day idle and 30-day absolute lifetime. Activity
  extends only the idle boundary, never the absolute boundary, and writes at most
  once per five minutes.
- Cookie mutations require a same-origin `Origin`, readable CSRF cookie, matching
  request header, and the bound server-side hash. An invalid explicit Bearer token
  is rejected and never falls back to the valid browser cookie.
- Sensitive browser operations require password plus TOTP step-up. The result is
  valid for at most ten minutes in that browser session and is not inherited by
  any other device or API token.
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
| Stolen browser cookie | Hash-only server row, idle/absolute expiry, revocation, session version | An active stolen cookie remains usable until expiry or revocation |
| CSRF | Strict same-origin check plus double-submit token bound to the session row | Compromised same-origin script can act with the user’s authority |
| Initial-password abuse | Forced setup allowlist enforced on every request | Initial password delivery remains an operational responsibility |
| TOTP replay | Monotonic accepted time-step counter | Concurrent use across multiple Controller replicas needs serialized database access |
| Recovery-code database disclosure | Keyed digest only; one-time consumption | JWT secret compromise permits offline verification attempts |
| Last-Owner race | `SELECT ... FOR UPDATE` around active Owners | SQLite is test-only and does not provide PostgreSQL row-lock semantics |
| Secret leakage | Explicit response DTOs and redacted append-only audit | Browser memory and clipboard remain endpoint risks |

## Migration and rollback request

Migration `0012_persistent_sessions` is reversible and follows
`0011_dashboard_query_indexes`. Before Staging authorization:

1. take an encrypted database backup and record its SHA-256;
2. restore it to an isolated PostgreSQL copy;
3. record table row counts and identity/audit integrity checks;
4. run `alembic upgrade 0012_persistent_sessions`;
5. validate users, audit rows, recovery-code hashes, and session consistency;
6. run `alembic downgrade 0011_dashboard_query_indexes`, validate compatibility, then
   upgrade again;
7. request a separate change window and rollback approval.

Do not run these steps against the current online Controller without explicit
authorization. Staging deployment is `NO-GO`; Production is `NO-GO`.
