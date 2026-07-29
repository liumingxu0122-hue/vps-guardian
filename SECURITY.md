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
- Keep per-port accounting disabled until the helper artifact and systemd units are
  checksum-verified in isolated Linux Staging. Never grant the Agent `CAP_NET_ADMIN`;
  use only the fixed socket-activated helper. Preserve non-Guardian nftables tables
  and qdiscs, and require independent approval for enforcement, reset, or shaping.
- Keep the formal Agent release-signing private key offline and outside Git, CI
  artifacts, images, logs, and Controller hosts. CI test keys are never release keys.
- Never reuse enrollment credentials for repair or decommission. Complete
  certificate removal only after matching CRL publication is independently verified.

The project never needs a provider account-wide object-storage token. Grant only object access to the dedicated backup bucket.

The port-traffic helper never needs Internet access or application credentials. Report
any path that permits arbitrary helper commands, arbitrary nftables/TC object names,
or self-approved enforcement as a security vulnerability.
