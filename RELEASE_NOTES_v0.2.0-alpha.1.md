# VPS Guardian v0.2.0-alpha.1

## English

VPS Guardian v0.2.0-alpha.1 packages the completed Phase 4B multi-VPS monitoring and controlled repair work. It is an Alpha / Developer Preview and is not recommended for direct production use.

### Included

- Multi-VPS host management with groups, tags, search, enable/disable, online filters, and sorting.
- One-time Agent enrollment tokens stored as SHA-256 digests and passed through protected token files.
- HTTP/HTTPS, TCP, ICMP, Docker, and systemd checks.
- SSRF, DNS rebinding, private-network, metadata, redirect, response-size, and CIDR allowlist defenses.
- Persistent alerts with deduplication, hysteresis, acknowledgement, silences, maintenance windows, recovery notifications, and restart persistence.
- Telegram, SMTP, and Webhook notification references, rate limits, retries, and local-only tests by default.
- Approval-backed Ed25519-signed repair tasks with nonce, expiry, requester/approver binding, audit, and bounded actions.
- Bilingual Hosts, Services, Alerts, and Settings pages.
- Agent dynamic service checks, host resource metrics, restart counters, and installer rollback.
- Nezha v2.3.0 architecture/deployment study.

### Installation

Use the versioned Compose bundle and verify `checksums.sha256` before extraction. Follow [the English quick start](docs/en/QUICKSTART.md) and [Agent installation](docs/en/AGENT_INSTALLATION.md). Never put passwords, tokens, private keys, or cloud credentials in command arguments, `.env`, Git, logs, or support bundles.

### Upgrade notes

This release contains the Phase 4B schema migration. Back up PostgreSQL and Restic data, verify an isolated restore, read `CHANGELOG.md`, and test the Compose configuration before upgrading. Keep an explicit rollback point. Do not assume Alpha releases have stable upgrade compatibility.

### Known limitations

Full CSR bootstrap, long-running multi-VPS validation, the seven-day Nezha comparison, cross-cloud automatic rebuild, production public deployment, and a complete automatic disaster-recovery loop are not complete. Phase 4C is not included in this release.

### Verification

Every uploaded asset is covered by `checksums.sha256`. The checksum file itself is intentionally excluded from its own checksum list.
