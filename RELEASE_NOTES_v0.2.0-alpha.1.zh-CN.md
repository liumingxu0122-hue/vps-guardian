# VPS Guardian v0.2.0-alpha.1

## 简体中文

VPS Guardian v0.2.0-alpha.1 打包已完成的 Phase 4B 多 VPS 监控和受控修复能力。本版本属于 Alpha / Developer Preview，不建议直接用于生产环境。

### 已包含

- 多 VPS 主机管理、分组、标签、搜索、启用/禁用、在线筛选和排序。
- 一次性 Agent 注册令牌，Controller 只保存 SHA-256 摘要，并通过受保护令牌文件传递。
- HTTP/HTTPS、TCP、ICMP、Docker 和 systemd 检查。
- SSRF、DNS 重绑定、私网、metadata、重定向、响应大小和 CIDR allowlist 防护。
- 持久化告警、去重、迟滞、确认、静默、维护窗口、恢复通知和重启后状态保持。
- Telegram、SMTP、Webhook 通知引用、限速、重试，默认仅允许本地 mock 测试。
- 带审批的 Ed25519 签名修复任务，包含 nonce、过期时间、请求人/批准人绑定、审计和受控动作。
- 双语 Hosts、Services、Alerts、Settings 页面。
- Agent 动态服务检查、主机资源指标、重启计数和安装失败回滚。
- 哪吒 v2.3.0 架构与部署研究。

### 安装

使用带版本号的 Compose bundle，并在解压前校验 `checksums.sha256`。请阅读[简体中文快速开始](docs/zh-CN/QUICKSTART.md)和 [Agent 安装](docs/zh-CN/AGENT_INSTALLATION.md)。禁止把密码、令牌、私钥或云凭据放入命令参数、`.env`、Git、日志或支持包。

### 升级说明

本版本包含 Phase 4B 数据库结构迁移。升级前备份 PostgreSQL 和 Restic 数据，完成隔离恢复校验，阅读 `CHANGELOG.md`，并先验证 Compose 配置。保留明确的回滚点，不要假定 Alpha 版本具备稳定升级兼容性。

### 已知限制

完整 CSR bootstrap、长期多 VPS 验证、7 天哪吒对比、跨云自动重建、生产公网部署和完整自动灾难恢复闭环尚未完成。Phase 4C 不包含在本版本中。

### 校验

所有上传资产都由 `checksums.sha256` 覆盖；校验文件本身有意不包含在自己的校验列表中。
