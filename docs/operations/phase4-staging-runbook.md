# Phase 4 Staging, rollback, coexistence, and recovery runbook

This runbook is intentionally non-executing. It defines the evidence required before any Staging
change. It does not authorize production, DNS, Komari, proxy-node, firewall, SSH, user, or global
runtime changes.

## Preconditions

- reviewed pull request and green CI;
- exact immutable commit and image digests;
- migration upgrade and downgrade tested;
- authenticated dashboard confirmed; anonymous management access rejected;
- fresh database backup, configuration backup, Secret-reference inventory, current image list,
  reverse-proxy/Gateway backup, and checksum manifest;
- current off-site repository access and isolated restore verified;
- rollback owner, rollback images, rollback migration point, and maximum outage agreed;
- non-Guardian service and Komari baseline captured;
- Owner credential available through a safe channel, with a separate recovery Owner.

If any item is absent, the deployment is NO-GO.

## Controlled deployment

1. Freeze the Staging change window and record UTC start.
2. Reconfirm non-Guardian containers, services, ports, networks, volumes, and Komari health.
3. Put the application into its documented migration mode; do not change host-global services.
4. Apply the reviewed migration and deploy one immutable release across Controller, Web, Gateway,
   and schema provenance.
5. Wait for health checks and verify restart counts before functional testing.
6. Verify login, unauthenticated `401`, invalid credential `401`, TOTP, CSRF, role/scope matrix,
   session revocation, and last-Owner protection.
7. Verify desktop/mobile deep links, Overview, Attention, hosts, services, alerts, incidents,
   approvals, recovery, security, users, agents, notifications, audit, and settings.
8. Verify both existing Agents, mTLS, heartbeat, metrics, checks, signed-task replay rejection,
   renewal, revocation at TLS handshake, and bounded non-destructive repair dry-run.
9. Exercise real event notifications through two configured channels, including retry and dead
   letter. A test-message-only result does not pass.
10. Recompare non-Guardian services and Komari. Any unexplained drift triggers rollback.

## Rollback

Rollback is an application and schema procedure, not a host reset:

1. stop the new Guardian application writers;
2. preserve failed-release logs and database evidence;
3. run the reviewed migration downgrade only if its data-loss analysis permits it;
4. otherwise restore the verified pre-deployment database into the isolated recovery path, validate
   it, then promote it through the approved recovery workflow;
5. redeploy the prior immutable Controller/Web/Gateway images;
6. verify authentication, API health, two Agents, CRL, alerts, audit, and backup markers;
7. confirm Komari and all non-Guardian services remain unchanged;
8. record actual interruption, data-loss window, RPO, RTO, and incident timeline.

Do not erase the failed deployment or evidence. Do not use `git reset`, unreviewed SQL, or an
unapproved production restore.

## Fault handling

| Symptom | Safe response |
| --- | --- |
| Migration fails | stop writers; preserve logs; execute reviewed downgrade/restore path |
| Revoked certificate connects | fail the security gate; restore previous Gateway; do not widen trust |
| CRL unreadable/reload error | keep ingress fail-closed; rollback Gateway material |
| Notification delivery fails | allow bounded retry; inspect dead letter; do not log channel secret |
| Controller database unavailable | stop repairs; require independently healthy recovery evidence |
| Agent reconnect storm | stop rollout batch; keep Komari; inspect bounded backoff and queue replay |
| Non-Guardian drift | rollback Guardian only; do not “repair” the unrelated service |
| Owner credential unavailable | use recovery Owner; do not disable the last Owner or disclose a password |

## Komari coexistence

Guardian is additive during Phase 4. Install only on explicitly selected low-risk nodes and keep
Komari running. Compare online state, resource metrics, latency, Agent overhead, missing data, false
alerts, and UI response by time window. A disagreement is evidence to investigate, not permission
to remove either Agent. No bulk rollout occurs before each batch passes.

## Runtime-data disk

Current root utilization is below the migration threshold and Docker is already on the secondary
filesystem, so no disk move is authorized.

If a later capacity review requires migration:

1. inventory Docker root, containerd root, PostgreSQL, Restic cache, logs, and image layers;
2. validate the target filesystem and free space;
3. take application/database backups and capture service state;
4. migrate Docker and containerd as separate reviewed changes, never by copying live databases;
5. use a checksum-preserving transfer, retain the old directory, and test startup/data integrity;
6. verify rollback before deleting any source data.

Seeing a second disk is not a migration trigger.

## Owner credential rotation

The existing Staging Owner credential is considered exposed. Rotate it only through an interactive,
non-logged channel:

1. confirm a separate active recovery Owner;
2. generate and enter the new password outside argv, Git, screenshots, and logs;
3. rotate the selected Owner password;
4. revoke its earlier sessions and verify they receive `401`;
5. sign in with the new credential and verify TOTP;
6. confirm the audit event without exposing the password.

This sprint cannot claim the rotation complete until a human performs and verifies these steps.
