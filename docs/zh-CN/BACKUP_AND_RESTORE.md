# 备份与恢复

[English](../en/BACKUP_AND_RESTORE.md) | [简体中文](BACKUP_AND_RESTORE.md)

VPS Guardian 支持 PostgreSQL 导出及 S3 兼容对象存储中的 Restic 快照。仓库凭据和 Restic 密码只能存放在 root 专用文件或 Secret Manager 中，禁止写入 Compose YAML、argv、Git、报告或日志。

每次备份应生成一致性数据库导出，只把预期项目数据加入 Restic，记录 snapshot ID，并按受控计划执行 `restic check`。对象存储应关闭公开访问，并在平台支持时使用不可变或最小权限凭据。

只有在全新临时目录和数据库完成隔离恢复、文件数量与 SHA-256 对比、Schema 验证及关键记录检查后，备份才可标记为 accepted。实测 RPO/RTO 是特定环境证据，不是通用保证。

保留策略、`forget`、`prune` 和仓库删除均为破坏性操作，必须显式审批。宣称生产就绪前，还应测试凭据丢失、仓库不可用和数据库损坏场景。
