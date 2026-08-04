# Alpha release signing trust anchor

`v0.4-alpha-release-ed25519.pem` is the public Ed25519 trust anchor for the
VPS Guardian v0.4 alpha release line. Its identifiers are:

- Key ID: `ed25519-sha256:3e3d878e37f3ababd96827441be8dae17bb397b8012e8f7de65331f2356e524a`
- PEM SHA-256: `c9fe05398821dc580aaebcda4cea64f7bf9c998dc59c898b4fcdf79aacec37b4`

The corresponding private key is stored outside the repository with access
restricted to its custodian. It is an Alpha/Developer Preview release key, not
an offline Production signing key. Every release manifest must be version-bound,
signed outside the repository, and verified with this exact public key before
publication.

Rotation requires adding a new public key and Key ID through review before any
artifact uses it. During an explicitly documented transition, installers may
accept both reviewed public keys; removing the old key requires a later reviewed
release after the transition window. Private keys must never enter Git, CI
artifacts, logs, command output, container images, or public release assets.
