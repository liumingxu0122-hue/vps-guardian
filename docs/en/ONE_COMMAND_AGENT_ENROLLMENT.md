# One-command Agent enrollment

[English](ONE_COMMAND_AGENT_ENROLLMENT.md) | [简体中文](../zh-CN/ONE_COMMAND_AGENT_ENROLLMENT.md)

## Scope and release gate

This workflow adds a server from **Hosts → Add server**, then produces one command for the intended Linux host. It is disabled by default. Enabling it requires a fixed release version, credential-free HTTPS asset URLs, a detached Ed25519 manifest signature, an independently pinned release public-key SHA-256, and exact SHA-256 values for the installer, both Agent architectures, the Controller CA, and Controller signing public key. A missing or placeholder value makes command issuance fail closed.

Supported targets are Ubuntu, Debian, Rocky Linux, AlmaLinux, RHEL, Fedora, and Alpine on `amd64` or `arm64`. `generic` is an explicit operator choice for another Linux distribution using systemd or OpenRC; it is not automatic compatibility.

This document does not authorize a Production deployment. Production remains behind the existing deployment and observation gates.

## Supported distributions

| Family selected in the UI | Accepted `/etc/os-release` IDs | Service manager |
| --- | --- | --- |
| Auto | Ubuntu, Debian, Rocky, AlmaLinux, RHEL, Fedora, Alpine | systemd or OpenRC |
| Debian | Ubuntu, Debian | systemd |
| RHEL | Rocky, AlmaLinux, RHEL | systemd |
| Fedora | Fedora | systemd |
| Alpine | Alpine | OpenRC |
| Generic | Any non-empty Linux ID after manual review | systemd or OpenRC |

## Security model

An Admin or Owner creates a Host. An Operator, Admin, or Owner can create its 10-minute enrollment session; only Admin/Owner can revoke, and a group-scoped Admin is limited to authorized groups. An optional source CIDR can bind use to the target server address. Regenerating a command immediately revokes the previous unused session.

The command contains one short-lived enrollment credential and is displayed once by the browser. The Controller stores only SHA-256 digests. The credential is sent in a request header, never a URL. After the Controller accepts a valid, host-bound CSR, the credential cannot be used again. A separately scoped continuation credential reports only `service_installed`, `service_started`, or a safe failure; it is hash-only, expires with the session, cannot bootstrap an identity, and is deleted after installation.

The Agent creates a P-256 TLS private key, CSR, and Ed25519 request-signing key locally. The Controller returns only a signed client certificate, Agent mTLS CA bundle, gateway endpoint, and bounded progress credential. The Agent verifies the certificate against its local private key, Agent mTLS CA, client-auth usage, SPIFFE Agent ID, Host binding, expiry, and a credential-free HTTPS gateway before writing a new identity directory atomically.

Enrollment uses two deliberately independent trust bundles:

- `enrollment_https_ca_bundle` authenticates the HTTPS Gateway transport, including hostname/SAN, validity, `serverAuth`, and the complete leaf/intermediate chain. Its public PEM is downloaded before any credential-bearing request and accepted only after the SHA-256 pinned in the authenticated one-command response matches.
- `agent_mtls_ca_bundle` authenticates Agent client identities after CSR issuance. It is returned inside the already authenticated Enrollment response, verified against the new client certificate, and stored separately. It never replaces the Enrollment HTTPS trust bundle.

The Gateway sends the leaf and required intermediates, but not the root. Private Staging roots may differ, and a rotation bundle may temporarily contain two approved roots. No Enrollment request uses `--insecure`, disables hostname verification, or follows redirects while carrying a token.

The installer:

- downloads a fixed release; it never resolves `latest`;
- verifies every downloaded artifact before execution or installation;
- refuses redirects on every request carrying an enrollment credential;
- rejects URL credentials, query strings, fragments, insecure TLS, unsupported architectures, and OS mismatches;
- runs the service as `vps-guardian-agent` with no ambient or bounding capabilities;
- writes private keys as mode `0600`;
- supports systemd and OpenRC with restart-on-failure;
- changes only VPS Guardian Agent files, its user/group when newly created, and its service entry;
- does not change SSH, firewall, SELinux, unrelated packages, unrelated services, Komari, DNS, CRL, or Controller credentials.

### Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Command copied to the wrong host | Host binding, 10-minute expiry, optional source CIDR, immediate revoke/regenerate | A copied command can be used first from an allowed source |
| Token leak through URLs or logs | Header-only transport, hash-only storage, safe errors, no token audit fields | The one-line command can remain in local shell history |
| Artifact substitution | Credential-free HTTPS, fixed version, independently pinned Ed25519 manifest signature, then exact SHA-256 | Formal release authority remains blocked until the offline release key is provisioned |
| Enrollment Gateway impersonation | Independently pinned Enrollment HTTPS CA bundle, hostname verification, and TLS 1.3 | HTTPS transport CA compromise remains a trust-root event |
| Agent identity CA confusion | Separate Agent mTLS CA DTO, filename, verification path, and rotation rules | Agent mTLS CA compromise remains an identity trust-root event |
| Private-key exfiltration | Keys generated locally, atomic mode-0600 files, non-root service | Root on the Agent host can read keys |
| Partial installation | Pre-change backup, checksum manifest, service-state capture, failure trap, scoped rollback | Host power loss can interrupt rollback; retain the backup directory |
| Cross-tenant enrollment | Host creation is Admin/Owner-only; enrollment issuance is Operator+, revocation is Admin+, and optional `group:<group>:enroll` narrows Admin scope | Correct group assignment remains an operator responsibility |
| Proxy source spoofing | Forwarded source is trusted only with the private gateway authentication header | Gateway secret compromise defeats forwarded-source assurance |

## Operator workflow

1. Publish immutable installer and Agent assets for the exact release. Sign the version-bound manifest with the offline release key, publish the detached signature, and record the signing-public-key and artifact SHA-256 values through the controlled release process.
2. Configure the `GUARDIAN_AGENT_INSTALL_*` and Controller trust asset settings. Leave `GUARDIAN_ONE_COMMAND_INSTALL_ENABLED=false` until validation is complete.
3. Back up the Controller database/configuration and record the current schema and images.
4. Apply migration `0014_agent_enrollment`; verify migration upgrade/downgrade in isolation.
5. Enable the feature in isolated Staging only.
6. In **Add server**, enter name, region/group, OS family, optional source CIDR, and notes.
7. Copy the displayed command to the intended host. Closing the dialog removes it from the browser view.
8. Observe the status timeline through `completed`. Confirm a fresh authenticated heartbeat and a unique Agent/certificate identity.
9. Revoke an unused command. For `failed`, `expired`, or `revoked`, generate a new command; the former command stays invalid.

The installer’s expected changed paths are:

```text
/usr/local/sbin/vps-guardian-agent
/etc/vps-guardian/agent/
/var/lib/vps-guardian/agent/
/var/log/vps-guardian/
/etc/systemd/system/vps-guardian-agent.service
# or /etc/init.d/vps-guardian-agent
/var/backups/vps-guardian-agent/
```

## Rollback

The installer creates a unique root-only directory below `/var/backups/vps-guardian-agent/`, copies prior project files and service definitions, and writes `SHA256SUMS`. On failure it stops the candidate service, restores only the Agent-scoped files and prior service enabled/running state, removes a user/group only if this run created it, and reports a safe failure when a valid progress credential remains.

Controller rollout rollback is separate:

1. disable one-command issuance;
2. revoke unused enrollment sessions;
3. keep enrolled Agent certificates intact unless a distinct revocation decision is approved;
4. roll back Web and Controller to the compatible image;
5. downgrade `0014_agent_enrollment` only after verifying the old Controller does not read its tables/columns;
6. validate login, health, existing Agent heartbeat, and audit append-only behavior.

Do not modify CRL, firewall, Komari, DNS, or unrelated services as part of this rollback.

## Upgrade, repair, certificate rotation, and uninstall

The integrated workflow now uses migration `0015_agent_maintenance` and is described
in [Agent maintenance and decommission](AGENT_MAINTENANCE_AND_DECOMMISSION.md).

Do not reuse an initial-enrollment command for an active Agent. Binary repair or upgrade must preserve the existing identity directory and use a separately approved, fixed-version artifact workflow. Certificate replacement uses the existing dual-identity rotation API; moving a Host between groups does not require reinstallation.

For uninstall, first complete the controlled certificate-revocation and CRL-publication workflow and verify the old identity is rejected. Then run the version-controlled `scripts/uninstall-agent.sh`. It stops and removes only the Agent service, binary, and Agent configuration, creates a checksummed root-only backup, and preserves local queue/state unless `--purge-local-state` is explicitly selected. The local script deliberately cannot claim Controller revocation by itself and never deletes Controller Host history or audit records.

If a bootstrap request times out, do not blindly replay it: the Controller may already have consumed the one-time token. Check the desensitized session status and Agent identity first, then revoke/regenerate if necessary.

## Manual fallback

If one-command issuance is disabled, use the established protected manual enrollment process in [Agent installation](AGENT_INSTALLATION.md). Keep the same fixed-version checksum verification, local private-key generation, unique per-host certificate, non-root service account, and post-install heartbeat checks. Never bypass TLS or reuse identity material.

## Troubleshooting

- **Command issuance returns 503:** immutable asset URLs/hashes are incomplete or the feature flag is off.
- **Command expired/revoked:** generate a new command; do not attempt to recover the old credential.
- **Source rejected:** verify the configured CIDR and that enrollment traffic uses the trusted Agent Gateway.
- **OS mismatch:** select the detected distribution family; use `generic` only after manual compatibility review.
- **Checksum/version mismatch:** stop. Republish or correct controlled release metadata; never skip verification.
- **CSR/certificate rejected:** verify clock synchronization, pinned CA, and that the command is running on the intended host.
- **Service failed:** inspect only the VPS Guardian Agent service and root-only backup manifest. The status timeline reports a safe step and rollback result without secrets.
- **No heartbeat after service start:** verify outbound DNS/HTTPS/time sync and recent Agent logs. Do not alter firewall or proxy policy automatically.
