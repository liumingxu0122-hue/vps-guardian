# Nezha 2.3.0 Isolated Benchmark

[English](NEZHA_BENCHMARK.md) | [简体中文](../../zh-CN/comparisons/NEZHA_BENCHMARK.md)

This protocol compares VPS Guardian with the pinned Nezha 2.3.0 study target under equal conditions. All runtime values remain `Pending`; no isolated deployment or 24-hour collection has passed preflight yet.

## Isolation rules

Use the same clean Linux capacity, agent count, heartbeat/check intervals, fault targets, and observation windows. Keep separate Compose projects, networks, volumes, service names, loopback-only high ports, and root-only credentials. Do not expose public DNS, reverse proxies, Docker sockets, terminals, remote commands, MCP, or production resources. Apply CPU, memory, disk, and log limits before startup.

## Measurements

| Measurement | VPS Guardian | Nezha 2.3.0 | Method / status |
| --- | --- | --- | --- |
| Dashboard install time | Pending | Pending | Clean snapshot, pull and startup separated |
| Agent install time and binary size | Pending | Pending | Same architecture and transfer path |
| Agent idle CPU / RSS / bytes per minute | Pending | Pending | Median, p95 and sample count after 15-minute warm-up |
| Metric refresh latency | Pending | Pending | Collection, receipt and UI timestamps |
| Offline and HTTP/TCP failure detection | Pending | Pending | Identical interval, thresholds and synthetic target |
| Recovery notification latency | Pending | Pending | Local mock receiver with retry timing |
| Duplicate, false and missed alerts | Pending | Pending | Fixed expected transition matrix |
| 24-hour storage growth | Pending | Pending | Volume/database bytes before and after 24 real hours |
| Controller/Dashboard CPU and RSS | Pending | Pending | Equal cgroup limits and agent count |
| Restart state consistency | Pending | Pending | Compare persisted hosts, alerts and audit state |
| Upgrade, rollback and uninstall residue | Pending | Pending | Fixed versions and a deliberately failed health gate |
| Identity, RBAC, tasks, approvals and audit | Pending | Pending | Security capability review, not a performance score |
| Restic/S3 disaster recovery | Pending | Not equivalent | Report capability difference without manufacturing parity |

## Interpretation

Measured, inferred, blocked, and pending results must remain separate. Missing features are not assigned synthetic performance values. A favorable implementation result does not establish production readiness. The 24-hour row can be completed only after real elapsed time, and the seven-day Guardian observation remains `Running/Pending` until seven real days have passed.
