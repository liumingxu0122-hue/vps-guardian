# VPS Guardian v0.4.0-alpha.1

VPS Guardian v0.4.0-alpha.1 is an Alpha/Developer Preview of the multi-VPS
operations, observability, traffic-accounting, and Agent-lifecycle work validated
in Staging. It is not recommended for Production.

## Included in this release

- Multi-VPS inventory with groups, labels, and operational filters.
- Persistent HTTP/HTTPS, TCP, ICMP, Docker, and systemd service checks.
- Persistent alerts with hysteresis, deduplication, acknowledgement, silencing,
  maintenance windows, and recovery notifications.
- Separation of requester and approver, Ed25519-signed tasks, TTL, nonce, and
  replay protection.
- CSR bootstrap with Agent-local private keys, mTLS, certificate renewal,
  rotation, revocation, and CRL publication.
- RX/TX accounting for TCP/UDP single ports and port ranges.
- Monitor-only traffic accounting, scheduled resets, historical aggregation,
  quotas, and quota alerts.
- One-command Linux Agent installation with a version-bound signed manifest.
- Repair, Reinstall, Identity Rotation, and approval-gated Decommission workflows.
- English and Simplified Chinese Web UI and documentation.

## Verification boundary

Automated checks passed for credential isolation, single-use/expiry/replay
behavior, approval separation, signed manifests, rollback boundaries, CRL gates,
and exact-path Decommission restrictions. Real Staging acceptance passed
one-command installation, local CSR/mTLS bootstrap, first heartbeat, Repair,
Reinstall with Host/history preservation, Identity Rotation, CRL publication,
and rejection of the old certificate at the TLS layer.

## Known limitations

- Real two-person `Decommission preserve/purge` is **PENDING HUMAN ACCEPTANCE**.
  Automated tests are not a substitute for two independently controlled people.
- Agent B/OpenRC acceptance on a real node is not complete.
- KVM whole-machine reboot acceptance is not complete.
- The included Alpha release signing key is not an offline Production key.
- Staging acceptance is not a Production deployment or Production-readiness claim.

Production remains **NO-GO**. No Production deployment is part of this release.
