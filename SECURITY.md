# Security Policy

## Supported versions

Only the newest public prerelease is evaluated for security fixes. Alpha releases are not production-supported.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, private infrastructure data, or personal information. Use GitHub's private vulnerability reporting feature for this repository. Include affected version, impact, reproduction steps, and a minimal sanitized proof of concept.

## Operator responsibilities

- Keep secrets in root-owned files outside Git and rotate them after suspected exposure.
- Restrict the dashboard and Agent gateway at the network boundary.
- Verify release checksums and review dependency and image scan output.
- Test backup restoration in an isolated environment.
- Require RBAC, approval, confirmation, and auditing for disruptive operations.

The project never needs a provider account-wide object-storage token. Grant only object access to the dedicated backup bucket.
