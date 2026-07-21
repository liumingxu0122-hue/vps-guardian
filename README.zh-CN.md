# VPS Guardian

VPS Guardian 是一个以安全为核心的 Linux VPS 集群监控、诊断与恢复控制平面。项目由 FastAPI Controller、PostgreSQL、Vue 运营面板和使用双向 TLS 的轻量 Go Agent 组成。

> 这是 Alpha / Developer Preview 版本，尚不建议用于生产环境。

[English](README.md) | [快速开始](docs/QUICKSTART.md) | [架构](docs/ARCHITECTURE.md) | [安全策略](SECURITY.md)

## 当前已实现

- Controller、Web、PostgreSQL 和 Linux Agent
- mTLS、RBAC、TOTP、CSRF 防护与登录限流
- 签名任务、Nonce 防重放、审批和追加式审计事件
- Agent 心跳、CPU、网络指标和持久化离线队列
- Restic + S3 兼容存储备份恢复，包括 Cloudflare R2
- Overview 运营面板，覆盖主机、拓扑、灾备、安全、告警和审计

## 当前未完成

- 大规模多 VPS 长期运行验证
- Telegram / 邮件告警闭环
- 完整服务级监控
- 自动化审批修复闭环
- 跨云厂商自动重建
- 生产级公网部署

## 最短安装

```sh
git clone https://github.com/<your-account>/vps-guardian.git
cd vps-guardian
cp .env.example .env
# 修改 .env 中的示例域名和 ACME 邮箱。
sudo sh scripts/generate-controller-secrets.sh ./secrets agents.guardian.example.com
sudo sh scripts/prepare-compose-secrets.sh --secrets-dir "$(pwd)/secrets"
docker compose build
docker compose up -d
docker compose exec -it controller guardian-admin create-user
```

管理员命令会交互询问邮箱和隐藏密码。禁止把密码写进命令参数、Git、日志或 `.env`。自动化场景只能使用绝对路径、仅 root 可读的临时密码文件，并在成功后销毁该临时文件。

公开端口前请完整阅读[快速开始](docs/QUICKSTART.md)；Agent 注册参见 [Agent 安装](docs/AGENT_INSTALLATION.md)，备份参见[备份与恢复](docs/BACKUP_AND_RESTORE.md)。

升级 Alpha 版本前必须备份数据库和 Controller 数据，并阅读 [CHANGELOG.md](CHANGELOG.md)。卸载时 `docker compose down` 默认保留 volume；删除 volume 会永久销毁数据，必须由运维人员单独确认。

本项目采用 Apache-2.0。第三方依赖继续遵循各自许可证，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
