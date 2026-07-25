# VPS Guardian and Nezha 2.3.0

This is a neutral, source-bounded study, not a claim that either product has passed the other's
test suite. Runtime values are marked `Pending` until both systems are measured in the same isolated
environment.

## Version and sources

- Nezha `v2.3.0` was published on 2026-07-21 as an immutable GitHub release:
  <https://github.com/nezhahq/nezha/releases/tag/v2.3.0>
- Official full change range:
  <https://github.com/nezhahq/nezha/compare/v2.2.10...v2.3.0>
- Official project and installation overview: <https://nezha.wiki/en_US/>
- Official Agent installation/configuration:
  <https://nezha.wiki/en_US/guide/agent.html> and
  <https://nezha.wiki/en_US/configuration/agent.html>
- Official server/group management:
  <https://nezha.wiki/en_US/guide/servers.html>
- Official service monitoring: <https://nezha.wiki/en_US/guide/services>
- Official notification and group documentation:
  <https://nezha.wiki/en_US/guide/notifications.html> and
  <https://nezha.wiki/en_US/guide/group.html>
- Official user, settings, and API documentation:
  <https://nezha.wiki/en_US/guide/user.html>,
  <https://nezha.wiki/en_US/guide/settings.html>, and
  <https://nezha.wiki/en_US/guide/api>
- Official task documentation: <https://nezha.wiki/en_US/guide/tasks.html>

Sources were reviewed on 2026-07-25. The official documentation is living documentation; a feature
documented there is not automatically attributed to the exact 2.3.0 change set. The release itself
links to the full commit comparison rather than a curated feature narrative.

## Capability study

| Area | Nezha 2.3.0 official evidence | VPS Guardian Phase 4 branch | Status |
| --- | --- | --- | --- |
| Installation | One-click Dashboard/Agent workflows across mainstream systems | Compose, explicit Secret files, separate Gateway, controlled admin bootstrap | Guardian is intentionally more explicit; elapsed install benchmark Pending |
| Service monitoring | HTTP GET, ICMP Ping, TCPing, SSL certificate state, latency/history | HTTP/TCP/ICMP plus structured Agent checks and alert/incident association | Comparable workflows; isolated correctness benchmark Pending |
| Notifications | Flexible HTTP methods/templates, notification groups, alert thresholds, recovery modes | Telegram, email, Discord, webhook, scope/severity filtering, bounded retry, dead letter, audit | Guardian code complete; real two-channel closure Pending |
| Multi-user | Administrator and standard users with owned resources and per-user Agent secret | Owner/Admin/Operator/Viewer plus explicit narrowing scopes, reauthentication, session revocation | Different tenancy models; API matrix tests pass locally |
| API | PATs with resource/action scopes, expiry, and optional server whitelist; documented admin APIs | session/Bearer API, role ceiling, explicit scopes, append-only audit | Runtime interoperability and throughput Pending |
| Agent identity | User/Agent connection secret in documented configuration | host-bound CSR, Agent-local private key, mTLS certificate, renewal, CRL | Guardian targets stronger identity assurance; current live CRL revalidation Pending |
| Remote operations | scheduled/triggered shell tasks, bulk execution, WebSSH/file features in official docs | fixed allowlisted repair actions, dry-run, risk evaluation, approval, signature, verification | Guardian deliberately trades flexibility for a smaller execution boundary |
| Alerts/incidents | threshold alerts, notification state change, task triggers | persistent alert lifecycle plus assigned incidents, strict state transitions, resolution/postmortem | Guardian incident workflow code complete; operational validation Pending |
| Approval/audit | Fine-grained PAT scopes are documented | risk-based approval, immutable audit events, task replay defense | Guardian-specific claim; comparative audit exercise Pending |
| Backup/recovery | Official task guide shows backup jobs as a scheduled-task use case | off-site Restic workflow, restore validation, recovery points, approval-separated restore | Current Guardian recovery exercise is NO-GO; no unsupported claim about Nezha |
| Public/mobile UX | Visitor visibility controls and responsive user frontend are documented | authenticated operations console with mobile drawer and bilingual navigation | Visual and accessibility matrix Pending |

## Measurement table

Only Guardian values below are current observations. They are not a same-host comparison.

| Metric | Nezha 2.3.0 | Guardian baseline | Guardian Phase 4 result |
| --- | ---: | ---: | ---: |
| Dashboard/Controller RSS | Pending | 84.2 MiB Controller | Pending Staging deployment |
| Agent binary size | Pending | Pending | Pending |
| Agent RSS/CPU | Pending | Pending | Pending |
| Web shared JS gzip | Pending | 85.42 kB | 89.66 kB |
| Web CSS gzip | Pending | 9.57 kB | 11.43 kB |
| Overview route gzip | Pending | 6.02 kB | 6.30 kB |
| Authenticated API P50/P95 | Pending | Pending | Pending |
| 13/100/500/1000-host response | Pending | theoretical only | Pending isolated load test |
| First-screen requests/paint | Pending | Pending | Pending browser trace |

The Phase 4 shared JS increase is about 5%; CSS gzip is about 19.4%; Overview gzip is about 4.7%.
All remain inside the sprint's per-item 20% review threshold. Routes remain lazy-loaded and no
large UI framework was added.

## Product direction

Guardian should earn an advantage through evidence in:

- certificate-backed Agent identity and revocation;
- least-privilege multi-user access;
- auditability and approval separation;
- incident and notification closure;
- constrained, reversible repair;
- verified off-site recovery.

It must not pursue those goals by sacrificing low Agent overhead, simple installation, fast daily
navigation, responsive mobile use, or bounded resource consumption. Nezha's mature one-click
installation, broad remote operations, service monitoring, notifications, and visitor experience
remain useful benchmarks.

## Remaining experiment

Run both reviewed immutable releases in an isolated network with identical host allocations and
sampling intervals. Measure cold/warm install time, image/binary size, idle and loaded RSS/CPU,
Agent network use, API latency, browser traces, notification latency, failure/recovery accuracy,
and 13/100/500/1000 synthetic-host behavior. Never connect the comparison environment to real
proxy nodes, production credentials, or customer systems.
