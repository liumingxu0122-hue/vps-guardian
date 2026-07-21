# VPS Guardian

[English](README.md) | [简体中文](README.zh-CN.md)

VPS Guardian is a security-first control plane for monitoring, diagnosing, and recovering fleets of Linux VPS hosts. It combines a FastAPI Controller, PostgreSQL, a Vue operations dashboard, and a small Go Agent secured with mutual TLS.

> **This is an alpha release and is not yet recommended for production use.**

![VPS Guardian dashboard in English](docs/assets/dashboard-en.png)

## Features

- Controller, Web dashboard, PostgreSQL, and Linux Agent
- mTLS, RBAC, TOTP, CSRF protection, and login rate limiting
- Signed tasks, nonce replay protection, approvals, and append-only audit events
- Agent heartbeat, CPU and network metrics, and a durable offline queue
- Restic backup and restore with S3-compatible storage, including Cloudflare R2
- Operations Overview with hosts, topology, disaster recovery, security, alerts, and audit data
- Phase 4B multi-host inventory, service checks, persistent alert state, notifications, and approval-backed repairs
- English and Simplified Chinese Dashboard, documentation, dates, numbers, and status messages

## Current limitations

- No sustained validation across a large multi-VPS fleet
- External Telegram, SMTP, and webhook delivery remains opt-in; default tests use local mocks
- Enrollment still requires a pre-issued mTLS bundle; CSR bootstrap is planned
- No automatic cross-cloud rebuilding or production-grade public deployment
- Experimental Windows SSH dashboard launcher

## Architecture

```mermaid
flowchart LR
  A[Linux Agents] -->|TLS 1.3 mTLS| G[HAProxy Agent Gateway]
  G --> C[FastAPI Controller]
  U[Browser] -->|HTTPS| W[Caddy and Vue Web]
  W --> C
  C --> P[(PostgreSQL)]
  B[Backup job] --> P
  B --> R[Restic and S3-compatible storage]
```

Read the [architecture guide](docs/en/ARCHITECTURE.md) and the [Phase 4B operations guide](docs/en/PHASE4B.md).

## Quick install

Requires Docker Engine 27+, Docker Compose v2, Git, OpenSSL, Python 3, two DNS names, 2 CPU cores, 4 GB RAM, and 20 GB free disk as a practical preview baseline.

```sh
git clone https://github.com/liumingxu0122-hue/vps-guardian.git
cd vps-guardian
cp .env.example .env
sudo sh scripts/generate-controller-secrets.sh ./secrets agents.guardian.example.com
sudo sh scripts/prepare-compose-secrets.sh --secrets-dir "$(pwd)/secrets"
docker compose build && docker compose up -d
docker compose exec -it controller guardian-admin create-user
```

The final command securely prompts for the administrator email and hidden password. Never put a password in argv, `.env`, Git, or logs. Read the [complete quick start](docs/en/QUICKSTART.md) before exposing ports.

## Agent enrollment

Create the host inventory entry, generate a short-lived enrollment bundle through an authorized Controller workflow, install the architecture-specific Agent, and verify heartbeat, certificate serial, metrics, and offline queue. See [Agent installation](docs/en/AGENT_INSTALLATION.md).

## Dashboard access

Open `https://<GUARDIAN_DOMAIN>/overview`. The first visit follows the browser language for Chinese locales and otherwise uses English. The upper-right language selector persists the explicit choice. The Windows SSH launcher remains Experimental.

## Backup and restore

Use restricted secret files, a bucket-scoped identity, Restic checks, and isolated restores with file, SHA-256, schema, and critical-record validation. See [Backup and restore](docs/en/BACKUP_AND_RESTORE.md).

## Security design

TLS 1.3 mTLS, signed tasks, replay defense, RBAC, TOTP, CSRF protection, rate limiting, approvals, and audit reduce blast radius. They do not replace host hardening. See the [security model](docs/en/SECURITY_MODEL.md) and [security policy](SECURITY.md).

## Roadmap

The next milestones cover long-running fleet validation, CSR-based enrollment bootstrap, isolated Nezha runtime benchmarks, cross-cloud recovery, and production deployment guidance. See the [Nezha study](docs/en/comparisons/NEZHA_STUDY.md) and [benchmark plan](docs/en/comparisons/NEZHA_BENCHMARK.md); unmeasured runtime values remain `Pending`.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), keep changes scoped, add proportional tests, and never submit live infrastructure data or credentials.

## License

Apache-2.0. Third-party components retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
