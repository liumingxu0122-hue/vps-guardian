# Security model

[English](SECURITY_MODEL.md) | [简体中文](../zh-CN/SECURITY_MODEL.md)

VPS Guardian assumes that managed hosts, networks, operators, and external storage can fail or be compromised independently. Its controls reduce blast radius but do not replace host hardening.

- TLS 1.3 and mTLS authenticate Agent ingress; certificate rotation and CRL checks limit stale identities.
- Signed tasks, nonces, expiry, and replay detection bind work to an authorized request.
- RBAC, TOTP, CSRF protection, login rate limiting, approval, and second confirmation protect operator actions.
- Append-only audit events record actor, action, resource, source, and outcome without translating raw evidence.
- Secrets stay server-side in restricted files or secret stores; the Web bundle must contain none.
- Backup credentials should be bucket-scoped and restores must be isolated and verified.

Report vulnerabilities privately according to the repository `SECURITY.md`. Do not include live credentials, private keys, personal data, or production evidence in an issue.
