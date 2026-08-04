# Agent repair, reinstall, identity rotation, and decommission

This workflow applies only to an existing Host and Agent. It never creates a second
Host, and it preserves metrics, alerts, checks, tasks, audit history, and the Host
record. It does not authorize Staging or Production execution.

## Authorization and credentials

- Viewer/Auditor access is status-only.
- Operator can issue `repair` only.
- Admin/Owner can issue repair, reinstall, and identity rotation, subject to
  `group:<name>:maintain` when present.
- Decommission additionally requires current step-up, an independently requested
  and decided `agent.decommission` approval bound to the Host, a checkbox, and the
  exact Host name.
- Approver status never starts execution automatically.

Enrollment, maintenance, progress, and decommission credentials are distinct.
They are Host-bound, hash-only in the Controller, optional-source-CIDR-bound,
single-use, and valid for at most 10 minutes. A credential of one kind is rejected
by every other kind. Plaintext appears only in the initial response and is destroyed
when the browser dialog closes.

## Release verification

HTTPS and Controller-pinned SHA-256 remain mandatory. Before any artifact checksum
is trusted, the script verifies a detached Ed25519 signature over the version-bound
install manifest with an independently pinned public-key SHA-256. A wrong key,
signature, manifest, version, architecture checksum, or artifact fails closed.
There is no skip flag.

CI creates a short-lived test signing key outside the uploaded artifact directory,
verifies positive and tampered cases, and destroys the private key. That proves the
mechanism, not release authority. Until an offline formal release private key and
public-key ceremony exist, **Formal artifact signing is BLOCKED**.

## Repair and reinstall state machine

1. consume the one-time session through current mTLS;
2. verify the signed manifest and fixed artifact;
3. back up the existing binary, configuration, identity link, and service state;
4. stop only `vps-guardian-agent`;
5. install the candidate binary;
6. for reinstall/rotation, generate a new key and CSR locally and use identity-version
   CAS to switch the generation atomically;
7. restart the Agent and wait for a Controller-observed post-change heartbeat;
8. leave the former identity `retiring`;
9. publish and verify the matching CRL, revoke the old identity, then finalize.

Failure restores only the Agent binary, configuration, identity link, and prior
service state. Network interruption leaves an auditable non-terminal or rolled-back
session. A restart never converts an incomplete session to success.

## Decommission

The command starts with current mTLS plus a decommission-only token, stops the Agent,
removes only the Agent service, binary, and configuration, and reports
`confirmation_pending` using the bounded continuation credential. Default mode
preserves `/var/lib/vps-guardian-agent`; purge mode removes that exact directory only.

Controller finalization requires matching CRL publication evidence. It then revokes
the certificate identity, cancels pending Agent tasks, disables the Host, and retains
all Controller history. A network failure remains `confirmation_pending` or `failed`;
it is never presented as completed. Any force-revoke path remains a separately
approved, audited operational action.

## Distribution evidence and remaining Staging gates

CI runs the filesystem, script, platform, signal-cleanup, and signature contract in
Ubuntu 24.04, Debian 12, Rocky 9, and Alpine 3.21 containers on amd64 and arm64.
Containers do not fake systemd/OpenRC. Real service-manager behavior, mTLS ingress,
heartbeat, CRL rejection, rollback after network loss, and unrelated-file invariance
remain required on two explicitly authorized Staging VPS nodes.

## PR #9 Staging acceptance status

Automated checks passed for enrollment and maintenance credential isolation,
single-use/expiry/replay behavior, approval separation, CRL publication gates,
signal cleanup, rollback boundaries, and decommission path restrictions.

Real Staging acceptance at commit `2122fa7fa91ed26e477a1e5cdf61262d2d1f0fde`
passed one-command enrollment, Agent-local key and CSR generation, first mTLS
heartbeat, repair, reinstall with Host/history preservation, identity rotation,
CRL publication, and rejection of the former certificate at the TLS layer.

Real two-person decommission preserve/purge is **PENDING HUMAN ACCEPTANCE**. It
must use two independently controlled people and accounts; automation must not
simulate separation of duties. Agent B/OpenRC and a KVM whole-machine reboot are
also not covered by this acceptance run. These remaining gates are not code-test
failures and do not authorize Production. Production remains **NO-GO**.
