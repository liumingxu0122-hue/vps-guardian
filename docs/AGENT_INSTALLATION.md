# Agent installation

The Agent is a Linux binary. Release assets are provided for `amd64` and `arm64`.

## 1. Verify the binary

Download the binary and `checksums.sha256` from the same release, then verify the exact file with `sha256sum --check`. Do not run an unverified binary.

## 2. Issue a unique identity

On the protected Controller host, issue one certificate and signing key per Agent:

```sh
sudo sh scripts/issue-agent-certificate.sh /protected/secrets/pki host-01 /protected/output/host-01
```

Transfer the output over a protected channel. Never reuse a private key across hosts. Record the displayed certificate fingerprint and enroll the host through the authenticated Controller workflow.

## 3. Install files

Place the binary at `/usr/local/bin/vps-guardian-agent`, configuration at `/etc/vps-guardian-agent/config.json`, identity files below `/etc/vps-guardian-agent/tls`, and the signing key as a root-only file. Use `deploy/agent-config.example.json` as the schema reference and replace every placeholder.

The Controller URL must use the configured Agent gateway DNS name. `ca_file` must contain the CA that signed the gateway certificate. Set `tls_server_name` to the same DNS name. Pin the Controller public signing key and the Agent certificate fingerprint.

## 4. Install the service

Review `deploy/systemd/vps-guardian-agent.service`, then use `scripts/install-agent.sh` or install equivalent paths manually. Validate with `systemd-analyze verify`, start the service, and confirm a heartbeat and an empty offline queue in Overview.

## Rotation and revocation

Issue a new identity before expiry and use the dual-identity rotation workflow. Revoke a compromised certificate with `scripts/revoke-agent-certificate.sh`, publish the updated CRL through your controlled deployment process, and verify the old identity is rejected. Never delete the CA database as part of rotation.
