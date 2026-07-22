# VPS Guardian v0.3.0-alpha.1

本次 Public Alpha 推进了多主机信任与运维链路。两台隔离的 staging VPS 已完成基于 CSR 的接入：一次性 Token 绑定主机，私钥仅在 Agent 本地生成，证书序列号相互独立；同时完成受限续签、身份原子切换、吊销、单调递增 CRL 发布和旧证书拒绝验证。

本版本还增加持久化的 Docker、systemd、HTTP、TCP 服务检查，告警迟滞、确认与静默状态，本机回调通知及恢复通知验证，以及职责分离的签名修复审批流程和修复后复检。完全重放同一任务不会产生第二次副作用，自然过期的任务也不会再次投递。

## 验证结果

- Python 268 项测试通过；本地跳过 17 项依赖特定环境的测试
- Ruff 与严格 Mypy 通过
- Go 格式检查、测试和 vet 通过
- Web 15 项单测、生产构建和 9 项 Playwright 场景通过
- Gitleaks 未发现敏感信息
- 两台 staging Agent 在线，八项服务检查正常，活跃任务积压为 0

## 已知限制

本版本仍为 Alpha，不建议用于生产环境。长周期集群验证、隔离的哪吒运行时基准、外部 Telegram/邮件投递、跨云重建和生产公网部署仍未完成。Staging 验收不代表允许进入生产。

请从[快速开始](docs/zh-CN/QUICKSTART.md)入手，再阅读 [Agent 安装](docs/zh-CN/AGENT_INSTALLATION.md)。下载后必须使用 `checksums.sha256` 校验全部文件。
