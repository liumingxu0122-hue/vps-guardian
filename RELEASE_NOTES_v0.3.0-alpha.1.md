# VPS Guardian v0.3.0-alpha.1

This Public Alpha advances the multi-host trust and operations path. Two isolated staging VPS instances completed CSR bootstrap with host-bound one-time tokens, locally generated private keys, distinct certificate serials, bounded renewal, atomic identity switching, revocation, monotonic CRL publication, and rejection of the retired certificate.

The release also adds persistent Docker, systemd, HTTP, and TCP service checks; alert hysteresis; acknowledgement and silence states; loopback notification delivery and recovery validation; and an approval-separated signed repair workflow with post-repair verification. Exact task replay produced no second side effect, and a naturally expired task was not delivered.

## Verification

- 268 Python tests passed; 17 environment-specific tests skipped locally
- Ruff and strict Mypy passed
- Go formatting, tests, and vet passed
- 15 Web unit tests, production build, and 9 Playwright scenarios passed
- Gitleaks found no secrets
- Two active staging Agents, eight current service checks, zero active task backlog

## Known limitations

This remains an alpha release and is not recommended for production use. Long-duration fleet validation, isolated Nezha runtime benchmarking, external Telegram/email delivery, cross-cloud rebuild, and production Internet deployment remain incomplete. Staging acceptance does not authorize production deployment.

Start with [Quickstart](docs/en/QUICKSTART.md), then follow [Agent installation](docs/en/AGENT_INSTALLATION.md). Verify every downloaded asset with `checksums.sha256`.
