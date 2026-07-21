# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and Semantic Versioning prerelease conventions.

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
