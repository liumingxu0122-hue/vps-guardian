# Nezha Benchmark Plan and Evidence

This document defines a reproducible comparison between VPS Guardian and an isolated Nezha V1 deployment. It deliberately records unavailable measurements as `Pending`; no synthetic numbers are used.

## Test boundary

The comparison must use the same clean Linux host, the same CPU/memory/storage limits, the same network path, and independent Compose projects, networks, volumes, ports, and credentials. It must not touch production Guardian, Sub2API, Komari, KobeHub, or other services. Dashboard and Agent versions must be pinned to the references in [NEZHA_STUDY.md](NEZHA_STUDY.md), and Guardian must be pinned to the commit under test.

The current Windows workstation has no Docker Engine. Therefore no clean Compose install, image build, or runtime benchmark has been claimed here. The CI `compose-and-images` job remains the required Linux gate.

## Measurements

| Measurement | VPS Guardian | Nezha | Status / method |
| --- | --- | --- | --- |
| Clean installation wall time | Pending | Pending | Fresh Linux VM; record command start/end and image pull time |
| Agent binary size | Pending | Pending | Record compressed artifact and installed binary sizes |
| Idle Agent CPU | Pending | Pending | 15-minute steady-state sample from cgroup and host counters |
| Idle Agent RSS | Pending | Pending | 15-minute steady-state RSS and cgroup memory |
| Agent network bytes/minute | Pending | Pending | Same heartbeat interval and no active checks |
| Metric refresh latency | Pending | Pending | Timestamp at collection, Controller receipt, and UI availability |
| Offline detection time | Pending | Pending | Block Agent network; measure first persisted offline state |
| HTTP/TCP failure detection | Pending | Pending | Identical target and check interval |
| Recovery notification time | Pending | Pending | Local mock receiver; include retry/backoff delay |
| Duplicate alert count | Pending | Pending | One outage/recovery episode over a fixed window |
| False positives / missed events | Pending | Pending | Fault-injection matrix with expected state transitions |
| 24-hour data growth | Pending | Pending | Measure database/data volume bytes before and after 24 h |
| Controller/Dashboard CPU and RSS | Pending | Pending | Same host limits and equivalent agent count |
| Upgrade duration and rollback | Pending | Pending | Pin old/new versions; force a failed health gate |
| Uninstall duration and residue | Pending | Pending | Verify service, files, volumes, audit/history retention |
| RBAC and agent identity review | Pending | Pending | Manual security checklist, not a performance score |
| Remote task safety review | Pending | Pending | Verify allowlists, approval, nonce and signature behavior |
| Audit completeness | Pending | Pending | Compare requested, approved, executed, and verified records |
| Backup/restore verification | Pending | Pending | Isolated Restic/DB restore and critical-record checks |

## Required scenarios

1. Install each system from a clean snapshot with no production DNS or firewall changes.
2. Enroll the same number of Agents and collect the same basic metrics for 15 minutes.
3. Run HTTP, TCP, and ICMP checks at equal intervals against local mock targets.
4. Inject an Agent outage, a target outage, delayed responses, and a recovery; record state transitions and notification retries.
5. Run the documented backup and isolated restore flow.
6. Upgrade and intentionally fail one health gate to verify rollback without touching dependencies.
7. Remove the test deployment and verify the documented residue and history behavior.

## Current repository gates

The Phase 4B checkout has passed the available local code gates: Python tests (247 passed, 16 skipped), Go formatting/vet/tests, Web typecheck/unit tests/production build, and the existing Playwright visual suite. These are implementation gates, not Nezha runtime benchmark results. Docker-based Compose validation is blocked on this workstation and must be rerun on Linux CI before any benchmark claim or clean-install acceptance.

## Interpretation rules

- Do not compare unlike feature sets or different check intervals.
- Report median and p95 for latency and resource samples, plus the sample count.
- Preserve raw, redacted measurements as CI artifacts.
- A skipped or unavailable measurement stays `Pending` and blocks a “complete benchmark” conclusion.
- A benchmark result does not authorize production deployment or a release tag move.
