# Backup and restore

VPS Guardian integrates Restic with local or S3-compatible storage. Backups are operator-controlled and are not a substitute for restore testing.

## Configure

Keep the Restic password in the generated secret file. Set `RESTIC_REPOSITORY` in `.env`; for S3-compatible storage, mount the access key, secret key, and region through `deploy/restic-s3.compose.yml`. Grant access only to the dedicated backup bucket or prefix.

Do not put object-storage credentials in environment files, command arguments, logs, reports, or Git. Public bucket access is unnecessary.

## Initialize and back up

Initialize a new repository once using Restic with file-based credentials. Then run the Compose backup profile or supplied systemd timer. A valid backup must include a database-consistent dump, metadata, and the controller recovery inputs expected by `guardian-recovery`.

Before accepting a snapshot:

1. Record the snapshot ID without recording credentials.
2. Run `restic check`.
3. Restore to a new isolated directory.
4. Verify file counts and SHA-256 hashes.
5. Restore PostgreSQL into an isolated database and verify schema and critical records.
6. Measure recovery point and recovery time from real timestamps.

## Restore

Never restore over a running database. Stop only project services in the approved maintenance window, preserve the current volumes, restore into new storage, validate ownership and permissions, and point services at the validated copy. Keep a complete rollback path until health, heartbeat, authentication, and audit checks pass.

The dashboard intentionally does not expose one-click `forget`, `prune`, or snapshot deletion. Apply retention only after backup acceptance and separate operator approval.
