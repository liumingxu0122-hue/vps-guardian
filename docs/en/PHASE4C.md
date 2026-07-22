# Phase 4C Staging Validation

[English](PHASE4C.md) | [简体中文](../zh-CN/PHASE4C.md)

Phase 4C adds CSR-based Agent bootstrap, bounded certificate renewal, controlled CRL publication, and a protocol for real two-host staging acceptance and an isolated Nezha 2.3.0 comparison. It does not authorize production deployment or a release.

## Current status

| Gate | Status | Evidence boundary |
| --- | --- | --- |
| CSR bootstrap implementation | Passed locally | P-256/RSA CSR validation, host-bound one-time token, gateway-only production ingress |
| Concurrent token consumption | Pending CI | PostgreSQL test uses two independent transactions; SQLite covers sequential reuse |
| Agent certificate renewal | Passed locally | New keys are generated locally; CA/SPIFFE binding is verified before atomic generation switch |
| CRL generation | Passed locally | Signed monotonic CRL preserves all earlier revocations |
| HAProxy CRL enforcement | Pending staging | Candidate validation and rollback workflow implemented; real TLS rejection not yet measured |
| Staging deployment | Blocked | Preflight did not establish a controlled SSH path to every registered staging host and found an unrelated-service baseline requiring confirmation |
| Agents enrolled by CSR in staging | 0 | No staging write was allowed after the blocking preflight |
| Nezha 2.3.0 isolated deployment | Pending | No runtime comparison has been claimed |
| 24-hour collection | Not started | Starts only after both isolated deployments pass preflight |
| Seven-day observation | Pending | Can be accepted only after seven real days have elapsed |

## CSR bootstrap boundary

An authorized operator creates a host and a short-lived enrollment token. The Controller stores only its SHA-256 digest. The installer reads the token from a mode-0600 file, generates the TLS and Ed25519 signing private keys locally, submits a CSR through the private Agent Gateway, and deletes the token file after use. The token is host-bound, revocable, rate-limited, and atomically consumed once.

Only the exact bootstrap path may reach the Agent Gateway without a client certificate. Every other Agent path requires a TLS 1.3 client certificate. The Controller additionally requires the private gateway authentication header in production, so the Web reverse proxy cannot be used to bypass this boundary.

## Renewal and revocation

The Agent renews inside a bounded pre-expiry window. A renewal request is authenticated by the active mTLS identity and its Ed25519 request signature, and includes proof of possession for the new signing key. The Controller uses an identity-version compare-and-swap. The Agent verifies the returned certificate against the pinned Agent CA, its private key, the expected SPIFFE URI, fingerprint, and encoded expiry before switching an atomic `identities/current` link. The previous generation is retained for rollback.

CRL publication is deliberately host-controlled. `guardian-admin build-agent-crl` produces a new candidate from a serial-number file and protected CA files. `scripts/publish-agent-crl.sh` validates the candidate and HAProxy configuration, atomically replaces the CRL, recreates only the Agent Gateway, and restores the previous CRL if health validation fails. Publishing a CRL and recording the corresponding Controller identity revocation are both audited operator actions.

## Staging acceptance protocol

Before the first write, every target must pass disk, inode, I/O, rollback-image, database-backup, SSH rollback, project-container, and unrelated-service baseline checks. The acceptance matrix then requires two real staging hosts with distinct certificate serials, fresh metrics, service checks, alert hysteresis, notification retry, approval separation, signed task execution, nonce replay rejection, and complete audit records.

Fault injection is limited to VPS Guardian or dedicated synthetic services. Root-disk filling, SSH interruption, host reboot, global firewall changes, production changes, and unrelated-service changes are prohibited.

## Observation conclusion

The current production conclusion remains **NO-GO**. Phase 4C is an alpha validation activity. A green CI run proves implementation gates only; it does not replace two-host staging evidence, a real notification delivery, the isolated comparison, or the required elapsed observation periods.
