# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and Semantic Versioning prerelease conventions.

## [0.2.0-alpha.1] - 2026-07-22

### Added

- Multi-VPS host inventory with groups, tags, enable/disable controls, search, online filters, and resource sorting.
- One-time Agent enrollment tokens with digest storage and protected token-file installation.
- HTTP/HTTPS, TCP, ICMP, Docker, and systemd service checks with SSRF, DNS rebinding, and CIDR allowlist defenses.
- Persistent alert state machine with deduplication, hysteresis, acknowledgement, silences, maintenance windows, and recovery notifications.
- Telegram, SMTP, and Webhook notification configuration using protected external references and local-only tests by default.
- Approval-backed Ed25519-signed repair tasks with nonce, expiry, requester/approver binding, and bounded actions.
- Bilingual Hosts, Services, Alerts, and Settings pages, plus Agent dynamic checks, resource metrics, and installer rollback.
- Nezha v2.3.0 architecture and deployment study.

### Known limitations

- Full CSR bootstrap, long-running multi-VPS validation, the seven-day Nezha comparison, cross-cloud rebuild, production public deployment, and a complete automatic disaster-recovery loop are not complete.

### 简体中文

- 多 VPS 主机管理、分组、标签、筛选和启用/禁用。
- 一次性 Agent 注册令牌及受保护文件安装流程。
- HTTP/HTTPS、TCP、ICMP、Docker、systemd 检查，以及 SSRF、DNS 重绑定和 CIDR allowlist 防护。
- 持久化告警状态机、去重、迟滞、确认、静默、维护窗口和恢复通知。
- Telegram、SMTP、Webhook 通知配置，默认只允许本地 mock 测试。
- 审批、Ed25519 签名、nonce、过期时间和受控修复动作。
- 双语 Hosts、Services、Alerts、Settings 页面，Agent 动态检查、资源指标和安装回滚。
- 哪吒 v2.3.0 架构与部署研究。

CSR bootstrap、长期多 VPS 真实运行验证、7 天哪吒对比基准、跨云自动重建、生产公网部署和完整自动灾难恢复闭环仍未完成。

## [Unreleased]

### English

- Added English and Simplified Chinese Dashboard resources with browser-language detection, an explicit persisted selector, and localized dates, numbers, durations, statuses, errors, loading, empty, offline, and permission states.
- Added paired English and Simplified Chinese core documentation and Dashboard screenshots built from fictional data.

### 简体中文

- 新增 English / 简体中文 Dashboard 资源，支持浏览器语言检测、手动选择持久化，以及日期、数字、时长、状态、错误、加载、空数据、断网和权限状态本地化。
- 新增成对的 English / 简体中文核心文档，以及使用虚构数据生成的 Dashboard 截图。

## [0.1.0-alpha.1] - 2026-07-22

### Added

- Initial public Developer Preview of Controller, Web, PostgreSQL, and Linux Agent.
- TLS 1.3 mutual authentication for Agent ingress, RBAC, TOTP, CSRF, login limiting, task signatures, nonce replay defense, approvals, and auditing.
- Host heartbeat, resource metrics, offline queue, operations overview, diagnostics, recovery workflows, and Restic S3-compatible backups.
- Generic Docker Compose bootstrap, secure administrator creation, Agent installation docs, CI, checksums, and release SBOM generation where supported.

### Known limitations

- No production support commitment or stable upgrade compatibility yet.
- Alert delivery, broad service monitoring, automated repair approval, cross-cloud rebuild, and sustained large-fleet validation remain incomplete.
