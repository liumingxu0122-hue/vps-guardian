# Nezha Study

This is an architectural study of the official Nezha V1 repositories and documentation. It is not a copied implementation and does not use Nezha branding or assets in VPS Guardian.

## Evidence snapshot

Research was performed on 2026-07-22 against the following immutable references:

| Component | Reference | Resolved commit | Release |
| --- | --- | --- | --- |
| Dashboard | `nezhahq/nezha` tag `v2.3.0` (annotated tag `e84c0fcb172ddacc5b78ed7987b0c34406f898c2`) | `5d7e8b58af927abd9a1e7381c1269c9f2256eae1` | [v2.3.0](https://github.com/nezhahq/nezha/releases/tag/v2.3.0), published 2026-07-21 |
| Agent | `nezhahq/agent` tag `v2.3.0` (annotated tag `8db0e95c912c8636a8ae6600857b468012b64a8a`) | `84e61fca84661503d324ae6ab00ca88e280e00a2` | [v2.3.0](https://github.com/nezhahq/agent/releases/tag/v2.3.0), published 2026-07-21 |

The official Dashboard image is `ghcr.io/nezhahq/nezha:v2.3.0`. The OCI index digest is `sha256:afd4058d06e2eec8da38ee3c159a6aae4ffeb3b8b8dcb02dbdc303b547aef76d`; the Linux/amd64 manifest is `sha256:dd923b4c7f8722e7708ae8088db6c59f4abf99704b03e129e91a82f401ff7167`. These are observations of the public GHCR manifest, not a claim that the image was run in this Windows checkout.

The official `nezha-agent_linux_amd64.zip` has SHA-256 `48353ada5e74ecaffb698d020e706376023837a9fc8e4c01fbb7f5e5893f32f5`, as listed in the release `checksums.txt`.

## Architecture and deployment

Nezha V1 is a Go Dashboard with a Go Agent. The Dashboard serves the web UI and receives Agent telemetry over its Agent connection endpoint. The official installation guide recommends a public Dashboard domain and a separate, non-CDN communication domain when a CDN is used; WebSocket support and firewall access to the Agent port are operational prerequisites. The published Docker build creates a small BusyBox-based image containing the platform-specific Dashboard binary, with `/dashboard/data` as its persistent volume and port 8008 exposed.

The Agent is installed as a platform-specific binary and can run under systemd or another service manager. Its configuration contains the Dashboard address, client secret/identity, UUID, TLS settings, update period, and optional custom probes. The official installer is interactive and downloads a script; VPS Guardian intentionally does not adopt an unchecked `curl | sh` workflow.

## Enrollment and communication

Nezha uses a Dashboard-issued client secret and an Agent UUID. The Agent maintains a long-lived connection and reports telemetry; the Dashboard can also push tasks to connected Agents. A communication domain should bypass a CDN when CDN WebSocket behavior is uncertain. The model is operationally simple, but the secret and binary trust chain remain deployment responsibilities.

VPS Guardian uses per-host enrollment records, one-time token digests, per-device mTLS identities, certificate revocation/rotation, and Ed25519-signed tasks. The current installer accepts a short-lived enrollment token through a protected file, but still requires a pre-issued certificate/key/CA bundle. A full CSR bootstrap endpoint is not yet implemented; this is an explicit Phase 4B limitation and must not be described as complete automatic enrollment.

## Metrics and history

Nezha advertises real-time server status, traffic, load, CPU, memory, swap, disk, process and connection counts, plus historical network latency charts. The service guide documents one-, seven-, and thirty-day latency views, with guest access limited to the shortest range. The Dashboard stores time-series history and applies retention through its own storage configuration.

VPS Guardian collects CPU/load, memory/swap, every readable mount and inode usage, network counters, boot time/uptime, OS, kernel, architecture, Agent version, queue depth, Agent RSS/CPU, and restart count. Missing values have explicit states instead of being coerced to zero, and retention is bounded by both age and row caps. These choices are intended to make stale or partial telemetry visible during recovery work.

## Service checks

Nezha service monitors support HTTP GET (including TLS certificate checks), TCPing, and ICMP Ping. A monitor can select a coverage rule or specific Agents and can show latency charts. Failure and delay notifications can trigger configured tasks.

VPS Guardian adds HTTP response assertions, TLS hostname/expiry checks, bounded response bodies, TCP and ICMP probes, and Agent-side Docker/systemd checks. Controller probes validate DNS results before connecting, reject credentials and query secrets in targets, block private/loopback/link-local/metadata networks by default, and require explicit CIDR allowlists for internal targets. ICMP permission failures are reported as `unsupported` rather than host failure.

## Alerts and hysteresis

Nezha notification rules can run continuously or once on a state change, and can invoke tasks on failure or recovery. The public guide describes host/resource thresholds, traffic thresholds, delay thresholds, and service failure notifications.

VPS Guardian persists an alert instance and transition history in PostgreSQL. Its state machine includes `ok`, `pending`, `firing`, `acknowledged`, `silenced`, and `resolved`, with failure/recovery thresholds, repeat intervals, maintenance windows, silences, acknowledgement, deduplication, and restart persistence. A single fingerprint is used for delivery deduplication, and recovery notifications are independently configurable.

## Notifications

Nezha supports configurable notification methods, placeholders, TLS verification, and webhook/Telegram/email-style integrations. Its documentation describes `Always` and `Once` trigger modes and optional task execution.

VPS Guardian stores only environment-variable or protected-file references for Telegram, SMTP, and webhook credentials. Test delivery is restricted to local mock endpoints unless an explicit external-delivery setting is enabled. Delivery attempts, response codes, retry state, rate limits, and type-only error summaries are recorded without storing secrets.

## Tasks and repair safety

Nezha supports scheduled tasks, trigger tasks, coverage rules, immediate execution, and shell/Batch commands. This is powerful for operations but means Dashboard credentials, Agent secrets, and task authorization require strong host controls.

VPS Guardian narrows the first repair set to diagnostics, allowlisted systemd/container restarts, disk cleanup preview plus a second confirmation, and Restic backup/check. Tasks carry requester, approver, target host, action ID, parameters, nonce, expiry, and an Ed25519 signature. High-risk requesters cannot self-approve. Arbitrary shell, reboot, SSH, firewall, DNS, Cloudflare, user, and global Docker changes are not registered actions.

## Storage, updates, and uninstall

Nezha's Dashboard image persists data in `/dashboard/data`; the official release workflow publishes binaries and multi-architecture GHCR images. The Agent release provides checksums for each platform and documents built-in or service-manager restarts. Backup, migration, and uninstall behavior must be verified against the version-specific official scripts before production use.

VPS Guardian keeps Controller state in PostgreSQL, uses bounded retention, and provides Restic backup/check with isolated restore validation. Its installer verifies SHA-256, runs the Agent as a non-root systemd user, records a rollback copy, and has a separate uninstall script that preserves Controller history and local state unless an explicit purge flag is supplied.

## Licensing and reuse boundary

The Dashboard and Agent repositories are Apache-2.0 licensed. If code is copied, the Apache license, copyright notices, and any applicable NOTICE material must be retained, and modified files must carry change notices. This project studies interfaces and operational trade-offs; it does not copy Nezha source, logo, screenshots, themes, or branding.

## Decision for VPS Guardian

Nezha is a useful reference for Agent coverage rules, service latency history, notification-triggered tasks, and a compact self-hosted deployment. VPS Guardian retains those ideas where they fit, while keeping its stronger enrollment identity separation, SSRF controls, approval/signature chain, persistent alert transitions, and secret-reference policy. Runtime and resource claims remain subject to the isolated benchmark in `NEZHA_BENCHMARK.md`.

### Official sources

- [Nezha Dashboard repository](https://github.com/nezhahq/nezha)
- [Nezha Agent repository](https://github.com/nezhahq/agent)
- [Dashboard installation guide](https://nezha.wiki/en_US/guide/dashboard.html)
- [Agent installation guide](https://nezha.wiki/en_US/guide/agent.html)
- [Service monitoring guide](https://nezha.wiki/en_US/guide/services)
- [Notification guide](https://nezha.wiki/en_US/guide/notifications.html)
- [Task management guide](https://nezha.wiki/en_US/guide/tasks.html)
