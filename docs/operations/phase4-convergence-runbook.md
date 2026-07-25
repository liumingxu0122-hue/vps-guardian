# Phase 4 convergence operations runbook

This runbook closes the operational work around the Phase 4 release candidate. It does not
authorize a Production deployment, DNS change, Gateway or reverse-proxy change, Komari change,
certificate replacement, CRL change, Agent reinstall, or an off-site backup write.

## Current release-candidate boundary

- Main merge commit: `c915f1da6c5bea57403067fc1c3085a4b50cbaca`
- Original PR #7 head: `5a970fc7a28e4e84d7b5b3bb50b0a3b1b72ac4b8`
- Staging release: `v0.4.0-phase4-stabilization-rc2-5a970fc`
- Schema: `0010_identity_recovery`
- Controller image:
  `sha256:baaf675181975523f33b5b76481110bd1e2aafd185020129bdf2ff4e7a8dc9f3`
- Web image:
  `sha256:eeb7d53b6468c0734bafb90a478d9607eab71136f94a8a7a2ed128711cbdd0cc`
- Production: **NO-GO**

Merging or tagging this source does not deploy it. Staging may continue to run the original PR
head while `main` contains it through the merge commit. Do not rebuild or redeploy Staging merely
to make those commit identifiers equal.

## Bounded Agent state-file ownership repair

This procedure is only for state files that are already proven to be ordinary, non-symlink files
inside the Agent-owned state directory and whose content must remain byte-for-byte unchanged.

### Read-only preflight

Resolve these values from the installed systemd unit; never guess them:

1. unit name, `User`, `Group`, `WorkingDirectory`, and `StateDirectory`;
2. canonical state-directory path;
3. canonical paths of `events.jsonl` and `action-state.json`;
4. file type, symlink status, owner, group, mode, inode, size, timestamps, SHA-256, and xattrs;
5. current Agent PID and whether any additional Agent process exists;
6. recent permission-denied logs and the Controller's last heartbeat;
7. active Agent identities and certificate count;
8. current Komari and unrelated proxy-business state.

Do not print either state file's content.

### Backup

Create a new root-owned directory with mode `0700`. Copy both files without transforming their
content and record their original metadata, xattrs, and SHA-256 in a manifest with mode `0400` or
`0600`. Verify the copied files against the manifest before changing ownership.

### Repair

Change only the two verified paths:

```text
chown <unit-user>:<unit-group> <state-dir>/events.jsonl
chown <unit-user>:<unit-group> <state-dir>/action-state.json
chmod 0600 <state-dir>/events.jsonl
chmod 0600 <state-dir>/action-state.json
```

Re-read inode and SHA-256 after the change. Both must match the preflight values. Confirm that no
other path's metadata changed.

Do not restart the Agent initially. Allow its normal retry loop to run. A restart of that Agent
unit alone is permitted only when evidence shows that the running process will not retry the
state-file read. Never restart the host, Docker, networking, Komari, or proxy services for this
repair.

### Three-cycle acceptance

For at least three complete expected heartbeat periods, record:

- timestamp, unit active state, PID, CPU, memory, and restart count;
- Controller heartbeat timestamp and fresh/stale classification;
- snapshot success and absence of new permission-denied messages;
- single Agent process, single active identity, and unchanged certificate;
- Komari and unrelated proxy-business health.

Pass only when all three periods have a new heartbeat and successful snapshot, with no duplicate
process, duplicate identity, new certificate, restart, or unrelated-service impact.

If the check fails, restore only the original owner/group from the verified backup, preserve the
logs, and stop. Do not expand the repair into reinstall, certificate, CRL, or identity changes.

## Legacy Staging credential expiry

The legacy password file remains a short-lived whole-environment rollback input. Its deadline is
`2026-07-29T04:00:00+08:00`. Before that deadline, an automated check may report metadata and
readiness but must not delete or move the file.

The metadata check records, without reading or printing content:

- canonical path, owner/group, mode, inode, and modification time;
- whether a process currently has the file open;
- whether a container mounts it;
- whether an active backup includes it;
- whether other copies exist in the approved search scope.

At the deadline, disposal requires all of the following:

1. Staging health and all four project services are healthy;
2. both Owners are active;
3. Recovery Owner TOTP login and the new staging-owner password work;
4. the old password, old Bearer credential, and old Cookie still return `401`;
5. Session revocation works;
6. rollback evidence is complete;
7. `main` contains the source running in Staging;
8. rollback to the legacy identity database is no longer planned.

The default accepted disposition is deletion from the active Staging host followed by a
metadata-only audit record. If retention is explicitly approved, move it only to an encrypted,
offline, access-controlled archive with its own expiry and access audit. Do not retain it in an
ordinary directory on the active host.

After the legacy environment is permanently retired, schedule another staging-owner password
rotation so that a future restoration of the old database cannot reactivate a useful credential.
That second rotation is a separate approved change.

## R2/Restic Secret input

The off-site Compose overlay consumes exactly five files:

- `restic-repository`
- `restic-password`
- `aws-access-key-id`
- `aws-secret-access-key`
- `aws-default-region`

`GUARDIAN_OFFSITE_SECRETS_DIR` must identify a dedicated, canonical, non-symlink directory owned by
`root:root` with mode `0700`. Each Secret must be a non-empty ordinary non-symlink file owned by
`root:root`, with mode `0400` or `0600`, no group/other permissions, and no NUL byte. A final
newline is optional.

The root-only input wizard must:

- read each value with terminal echo disabled;
- keep values out of shell history, argv, environment files, Git, logs, and command output;
- create each file through a root-only temporary file and atomic rename;
- validate metadata before and after the rename;
- report only that a named Secret is configured, never its content, size, or digest;
- fail closed and remove only its own incomplete temporary file on interruption.

The operator must provide the Cloudflare Account ID, R2 S3 endpoint, dedicated bucket, isolated
prefix, least-privilege key pair, Restic repository URI, independent Restic password, region,
retention policy, and an approved backup/restore window.

Before any write, inspect the target repository:

- if it is empty, stop and obtain a separate approval before `restic init`;
- if it is non-empty, do not initialize it; verify that it is the intended Restic repository;
- never overwrite or adopt an unrelated repository automatically.

Completing Secret input leaves Offsite DR at **READY FOR HUMAN INPUT**. It does not authorize an
off-site snapshot.

## Off-site restore acceptance

After separate approval:

1. create a database-consistent off-site snapshot;
2. run `restic check --read-data`;
3. restore into new isolated storage and a new database;
4. start Controller and Web only on an isolated network or loopback ports;
5. verify health, `0010_identity_recovery`, authentication, critical inventory, and checksums;
6. measure and record actual off-site RPO and RTO;
7. destroy only the isolated test environment after its evidence is accepted.

A same-host Restic repository is a rollback aid, not off-site disaster recovery evidence.

## 中文执行摘要

- 第二 Agent 只允许修改 `events.jsonl` 与 `action-state.json` 的属主、属组和 `0600`
  权限；内容、inode、SHA-256、证书、身份与其他文件不得改变。
- 修改前必须创建 `root:root 0700` 备份目录并验证清单；修改后观察至少三个完整心跳周期。
- 旧密码文件在 `2026-07-29 04:00 +08:00` 前只检查、不删除；到期后通过全部身份、
  Session 与回滚门禁才可删除或转入加密离线归档。
- R2 输入只能使用五个文件型 Secret，必须无回显、无 argv、无日志、无 Git、无
  `.env`，且不得输出长度或哈希。
- 未经另行批准，不执行 `restic init`、真实异地备份或恢复。
- 当前 RC 仍是候选版本；Production 始终为 **NO-GO**。
