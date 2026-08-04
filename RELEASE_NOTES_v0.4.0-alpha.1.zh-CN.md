# VPS Guardian v0.4.0-alpha.1

VPS Guardian v0.4.0-alpha.1 是经过 Staging 验收的多 VPS 运维、长期观测、
端口流量统计和 Agent 生命周期功能的 Alpha/Developer Preview。本版本不建议
用于 Production。

## 本次发布内容

- 支持多 VPS 清单、分组、标签和运维筛选。
- 持久化 HTTP/HTTPS、TCP、ICMP、Docker 和 systemd 服务检查。
- 持久化告警、迟滞、去重、确认、静默、维护窗口和恢复通知。
- 申请人与批准人职责分离、Ed25519 签名任务、TTL、nonce 和防重放。
- CSR Bootstrap、Agent 本地私钥、mTLS、证书续签、轮换、吊销和 CRL 发布。
- 按 TCP/UDP 单端口或端口范围统计 RX/TX 流量。
- Monitor-only 流量统计、周期重置、历史聚合、配额和配额告警。
- 使用版本绑定签名清单的一条命令 Linux Agent 安装。
- Repair、Reinstall、Identity Rotation 和审批门禁 Decommission 工作流。
- English 与简体中文 Web UI 和文档。

## 验证边界

自动化检查已覆盖凭据隔离、单次使用/过期/防重放、审批职责分离、签名清单、
回滚边界、CRL 门禁和 Decommission 精确路径限制。真实 Staging 已通过一条命令
安装、本地 CSR/mTLS Bootstrap、首次心跳、Repair、保留 Host/历史的 Reinstall、
Identity Rotation、CRL 发布和 TLS 层旧证书拒绝。

## 已知限制

- 真实双人 `Decommission preserve/purge` 仍为 **PENDING HUMAN ACCEPTANCE**；
  自动化测试不能替代由两名独立控制人员完成的验收。
- Agent B/OpenRC 真实节点验收尚未完成。
- KVM 整机重启验收尚未完成。
- 本版本使用的 Alpha Release 签名密钥不是离线 Production 密钥。
- Staging 验收不代表 Production 部署，也不代表 Production Ready。

Production 继续为 **NO-GO**；本次发布不包含任何 Production 部署。
