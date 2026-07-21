# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and Semantic Versioning prerelease conventions.

## [0.1.0-alpha.1] - 2026-07-22

### Added

- Initial public Developer Preview of Controller, Web, PostgreSQL, and Linux Agent.
- TLS 1.3 mutual authentication for Agent ingress, RBAC, TOTP, CSRF, login limiting, task signatures, nonce replay defense, approvals, and auditing.
- Host heartbeat, resource metrics, offline queue, operations overview, diagnostics, recovery workflows, and Restic S3-compatible backups.
- Generic Docker Compose bootstrap, secure administrator creation, Agent installation docs, CI, checksums, and release SBOM generation where supported.

### Known limitations

- No production support commitment or stable upgrade compatibility yet.
- Alert delivery, broad service monitoring, automated repair approval, cross-cloud rebuild, and sustained large-fleet validation remain incomplete.
