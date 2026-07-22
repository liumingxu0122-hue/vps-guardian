# 快速开始

[English](../en/QUICKSTART.md) | [简体中文](QUICKSTART.md)

本指南用于搭建单节点 Developer Preview，不是生产加固指南。

## 安装

安装 Docker Engine 27+、Docker Compose v2、Git、OpenSSL、Python 3 和 `flock`，并为 Dashboard 与 Agent 入口准备不同域名。

```sh
git clone https://github.com/liumingxu0122-hue/vps-guardian.git
cd vps-guardian
cp .env.example .env
chmod 0600 .env
# 替换 .env 中全部示例值；不得在其中写入 Secret。
sudo sh scripts/generate-controller-secrets.sh ./secrets agents.guardian.example.com
sudo sh scripts/prepare-compose-secrets.sh --secrets-dir "$(pwd)/secrets"
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
docker compose exec -it controller controller-entrypoint guardian-admin create-user
```

管理员命令会交互询问邮箱、角色、TOTP 选项及隐藏密码。禁止把密码写入 argv、`.env`、Git、Shell 历史或日志。等待 `database`、`controller`、`agent-gateway` 和 `web` 全部健康后，打开 `https://<GUARDIAN_DOMAIN>/overview`。

升级前必须验证备份与恢复，阅读 `CHANGELOG.md`，检出明确版本，重新构建并只重建 Guardian 服务。保留数据卸载使用 `docker compose down`；快速流程有意不包含 volume 删除。

Windows SSH Dashboard 启动脚本仍为 Experimental，必须显式传入 SSH 目标、密钥路径、Dashboard 域名和远端端口。
