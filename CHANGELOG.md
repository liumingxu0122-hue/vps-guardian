# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and Semantic Versioning prerelease conventions.

## [Unreleased]

## [0.3.0-alpha.1] - 2026-07-23

### English

- Added English and Simplified Chinese Dashboard resources with browser-language detection, an explicit persisted selector, and localized dates, numbers, durations, statuses, errors, loading, empty, offline, and permission states.
- Added paired English and Simplified Chinese core documentation and Dashboard screenshots built from fictional data.
- Added host-bound CSR bootstrap, locally generated Agent private keys, bounded certificate renewal with atomic identity generation switching, and controlled monotonic CRL publication.
- Added Phase 4C bilingual staging and Nezha 2.3.0 benchmark documents. Runtime acceptance remains blocked or pending where real evidence is unavailable.
- Validated two real staging Agents through CSR bootstrap, renewal, revocation, CRL enforcement, eight service checks, alert recovery, approval-separated repair, exact task replay idempotency, and TTL rejection.
- Preserved post-repair verification steps when an approved runbook is converted into signed Agent tasks.

### 简体中文

- 使用两台真实 staging Agent 验证 CSR 接入、续签、吊销、CRL 拦截、八项服务检查、告警恢复、职责分离审批修复、任务重放幂等和 TTL 拒绝。
- 修复审批通过后丢失 runbook 复检步骤的问题，确保修复操作和 postcheck 都转换为签名 Agent 任务。

- 新增 English / 简体中文 Dashboard 资源，支持浏览器语言检测、手动选择持久化，以及日期、数字、时长、状态、错误、加载、空数据、断网和权限状态本地化。
- 新增成对的 English / 简体中文核心文档，以及使用虚构数据生成的 Dashboard 截图。
- 新增主机绑定 CSR Bootstrap、Agent 本地生成私钥、带原子身份代际切换的受限证书续签，以及受控、单调递增的 CRL 发布流程。
- 新增 Phase 4C 双语 staging 和哪吒 2.3.0 基准文档；没有真实证据的运行时验收继续明确标记为阻塞或 Pending。

## [0.1.0-alpha.1] - 2026-07-22

### Added

- Initial public Developer Preview of Controller, Web, PostgreSQL, and Linux Agent.
- TLS 1.3 mutual authentication for Agent ingress, RBAC, TOTP, CSRF, login limiting, task signatures, nonce replay defense, approvals, and auditing.
- Host heartbeat, resource metrics, offline queue, operations overview, diagnostics, recovery workflows, and Restic S3-compatible backups.
- Generic Docker Compose bootstrap, secure administrator creation, Agent installation docs, CI, checksums, and release SBOM generation where supported.

### Known limitations

- No production support commitment or stable upgrade compatibility yet.
- Alert delivery, broad service monitoring, automated repair approval, cross-cloud rebuild, and sustained large-fleet validation remain incomplete.
