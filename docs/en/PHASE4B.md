# Phase 4B Operations Guide

Phase 4B adds real fleet inventory, selected-agent service checks, persistent alerts, notification delivery, and an approval-backed repair loop. It does not change the `v0.1.0-alpha.1` tag or any production infrastructure.

## Host lifecycle

An administrator creates an inventory record, optionally assigns a group and tags, and requests a short-lived enrollment token. The Controller stores only a SHA-256 digest. The token is bound to that host, expires, and is atomically consumed once. A revoked Agent may re-enroll with a new identity generation; an active Agent cannot be replaced. Never put the token in a shell command or long-lived configuration. Use the generated `--enrollment-token-file` bundle argument and remove the file after installation.

Hosts expose explicit data states: `normal`, `no_data`, `stale`, `offline`, and `agent_error`. Inventory filters support search, group, tag, enabled state, connectivity, and CPU/memory/disk/status ordering. Deletion is limited to never-enrolled records; disabling preserves history and audit.

### Enrollment boundary

The Controller issues a short-lived token and the generated command passes it through a mode-0600 token file. The current production installer still requires a pre-issued mTLS certificate, private key, and CA bundle to call the enrollment endpoint. A full CSR bootstrap flow that creates those artifacts on the target host is not implemented yet; certificate rotation and revocation remain Controller-governed operations.

## Metrics and retention

The Agent reports CPU/load, memory/swap, every readable mount and inode usage, network counters, boot time/uptime, OS, kernel, architecture, Agent version, queue depth, Agent RSS/CPU, and restart count. Missing values are not converted to zero. Controller retention is bounded by both age and per-host/per-check row caps.

## Service checks

Checks support HTTP/HTTPS, TCP, ICMP, Docker, and systemd. HTTP targets reject credentials, query secrets, redirects to unsafe schemes, oversized bodies, and unapproved private or metadata addresses. DNS results are checked before each connection and an explicit CIDR allowlist is required for internal targets. Docker and systemd checks require a registered host and Agent allowlist entry. ICMP permission failures are reported as `unsupported`, not as host offline.

## Alert state

Alert instances are keyed by a stable fingerprint and stored in PostgreSQL. Failure and recovery hysteresis, deduplication, repeat intervals, maintenance windows, silences, acknowledgement, firing, and resolved transitions survive Controller restarts. Every transition has a reason and timestamp. Recovery notifications are scheduled only when the rule enables them.

## Notifications

Telegram, SMTP, and generic webhook channels store only environment-variable or protected-file references. Delivery records contain attempt count, status, response code, next retry time, and a type-only error summary. Retries use bounded exponential backoff and channel rate limits. Test notifications are forced to local mock targets; external delivery requires the explicit `GUARDIAN_EXTERNAL_NOTIFICATIONS_ENABLED=true` deployment setting.

## Repair loop

The bounded loop is detection -> diagnostics -> recommendation -> approval -> signed task -> Agent execution -> recheck -> audit -> success or escalation. Registered actions are diagnostics, restart of an allowlisted systemd service or Docker container, disk cleanup preview, second-confirmed restricted cleanup, and Restic backup/check. Arbitrary shell, reboot, SSH, firewall, DNS, Cloudflare, user, and global Docker configuration changes are not registered actions. High-risk requesters cannot approve their own work. Task signatures bind requester, approver, approval, target host, nonce, expiry, and parameters.

## Clean installation evidence

The repository includes a non-root systemd unit, SHA-256 artifact verification, protected key modes, an automatic installer rollback, and `scripts/uninstall-agent.sh`. The uninstall command preserves Controller history and local queue/state unless `--purge-local-state` is explicitly supplied. A Docker-based clean installation remains a required Linux/CI gate when Docker Engine is available; a Windows checkout without Docker must be reported as blocked rather than represented as a successful clean install.

## Linux/CI validation note

The `compose-and-images` CI job is the authoritative clean-install gate. It must run on a Linux runner with Docker Engine and Compose v2, build the database/controller/web images, and preserve the logs as CI evidence. Local Windows checks cover source-level behavior only; they cannot replace image builds, health checks, migration startup, or isolated rollback validation.
