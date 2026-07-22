# Agent installation

[English](AGENT_INSTALLATION.md) | [简体中文](../zh-CN/AGENT_INSTALLATION.md)

Create the host inventory entry in the Dashboard, then generate its short-lived enrollment bundle. Transfer the versioned Agent binary, checksum, Controller public key, server CA, and mode-0600 enrollment-token file over a protected channel. Never put the token in a command argument or long-lived configuration.

Run the generated `scripts/install-agent.sh` command as root. The installer verifies the binary checksum and server CA, generates a P-256 TLS key, CSR, and Ed25519 signing key on the Agent host, and submits the CSR through the Agent Gateway. Private keys never leave the host. The token file is deleted after the request and cannot be reused.

Identity files use generation directories under `/etc/vps-guardian-agent/identities`. The `current` symbolic link selects the active generation. Keys are protected from other users, and the previous generation remains available after renewal for controlled rollback. Public CA files live separately under the trust directory.

The Agent renews inside the configured pre-expiry window. The Controller requires the active mTLS identity, signed request, new CSR, new Ed25519 proof of possession, and an identity-version compare-and-swap. Before switching, the Agent validates the returned key pair, pinned CA, client-auth usage, SPIFFE identity, fingerprint, and encoded expiry. A renewal failure leaves the current generation active and applies a bounded retry delay.

Certificate revocation is a controlled operator workflow. Build and validate a monotonic CRL candidate, publish it with `scripts/publish-agent-crl.sh`, confirm the Agent Gateway is healthy and rejects the old certificate, then record the matching identity revocation through the authorized Controller API. Do not run `forget`, `prune`, firewall changes, or unrelated-service operations as part of Agent identity maintenance.

After installation, verify a fresh heartbeat, distinct Agent ID and certificate serial, metrics, service results, restart persistence, and an empty offline queue. Revoke unused enrollment material. Never reuse one identity across hosts, disable certificate verification, or place keys in Git, shell history, logs, screenshots, or support bundles.
