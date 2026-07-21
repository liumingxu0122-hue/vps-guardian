# Backup and restore

[English](BACKUP_AND_RESTORE.md) | [简体中文](../zh-CN/BACKUP_AND_RESTORE.md)

VPS Guardian supports PostgreSQL exports and Restic snapshots in S3-compatible object storage. Keep repository credentials and the Restic password in root-only files or a secret manager, never in Compose YAML, argv, Git, reports, or logs.

Each backup run should create a consistent database export, add only the intended project data to Restic, record the snapshot ID, and run `restic check` on a controlled schedule. Use immutable or least-privilege bucket credentials where supported and keep public access disabled.

A backup is accepted only after an isolated restore into a new temporary directory and database, file-count and SHA-256 comparison, schema validation, and checks of critical records. Record measured RPO and RTO as environment-specific evidence, not universal guarantees.

Retention, `forget`, `prune`, and repository deletion are destructive operations and require explicit approval. Test credential loss, repository unavailability, and database corruption before claiming production readiness.
