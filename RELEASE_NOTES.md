# Release notes index

## Unreleased Phase 4 Agent lifecycle acceptance

Automated validation passed for enrollment/maintenance credential isolation,
approval separation, CRL gates, rollback, and decommission path boundaries. Real
Staging at fixed commit `2122fa7` passed one-command enrollment, local CSR/mTLS
bootstrap, repair, reinstall, identity rotation, CRL publication, and rejection
of the old certificate. Real two-person decommission preserve/purge is
**PENDING HUMAN ACCEPTANCE**; Agent B/OpenRC and KVM whole-machine reboot are not
covered. This is not a Production release or Production-readiness declaration.
Production remains **NO-GO**.

### 未发布的 Phase 4 Agent 生命周期验收

自动化验证已覆盖并通过注册/维护凭据隔离、审批职责分离、CRL 门禁、回滚和
退役路径边界。固定提交 `2122fa7` 已在真实 Staging 通过一条命令注册、本地
CSR/mTLS Bootstrap、Repair、Reinstall、身份轮换、CRL 发布和旧证书拒绝。
真实双人 Decommission preserve/purge 为 **PENDING HUMAN ACCEPTANCE**；
Agent B/OpenRC 和 KVM 整机重启尚未覆盖。本说明不代表 Production 发布或
Production Ready；Production 继续为 **NO-GO**。

Current release: [v0.3.0-alpha.1](RELEASE_NOTES_v0.3.0-alpha.1.md) | [简体中文](RELEASE_NOTES_v0.3.0-alpha.1.zh-CN.md)

# v0.1.0-alpha.1 / Public Alpha

## English

This first Developer Preview packages the Controller, Vue operations dashboard, PostgreSQL, Linux Agent, mTLS Agent gateway, security controls, durable offline queue, approvals/audit trail, and Restic S3-compatible backup workflows. Start with `docs/QUICKSTART.md` and verify every downloaded file against `checksums.sha256`.

Known limitations: production Internet deployment, large-fleet endurance, complete service monitoring, end-to-end Telegram/email alerts, automated approval/repair, and cross-cloud rebuild are not complete. The upgrade plan is to stabilize installation and migrations, expand alert and service coverage, and validate sustained multi-host operation before a beta.

## 中文

首个开发者预览版包含 Controller、Vue 运营面板、PostgreSQL、Linux Agent、mTLS Agent 网关、安全控制、持久化离线队列、审批/审计以及 Restic S3 兼容备份流程。安装请从 `docs/QUICKSTART.md` 开始，并使用 `checksums.sha256` 校验全部下载文件。

已知限制：生产级公网部署、大规模长期运行、完整服务监控、Telegram/邮件告警闭环、自动审批修复和跨云重建尚未完成。后续将先稳定安装与迁移流程，再扩展告警和服务覆盖，完成持续多主机验证后进入 Beta。
