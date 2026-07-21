# Phase 4B 运维说明

## Linux/CI 验证说明

`compose-and-images` CI job 是干净安装的权威门禁，必须在带 Docker Engine 和 Compose v2 的 Linux runner 上构建 database/controller/web 镜像，并保留日志作为证据。Windows 本地检查只能覆盖源码行为，不能替代镜像构建、健康检查、迁移启动或隔离回滚验证。

Phase 4B 提供真实的多主机清单、指定 Agent 的服务检查、持久告警、通知投递和带审批的修复闭环，不移动 `v0.1.0-alpha.1` 标签，也不改变生产基础设施。

## 主机生命周期

管理员创建主机清单后签发短时一次性注册令牌。Controller 只保存 SHA-256 摘要；令牌绑定主机、会过期并以原子方式消费一次。已吊销 Agent 可以用新的身份代次重新注册，活动 Agent 不能被覆盖。令牌不应进入 Shell 命令或长期配置，使用生成的 `--enrollment-token-file` 安装包参数，安装后删除令牌文件。

主机数据状态明确区分 `normal`、`no_data`、`stale`、`offline` 和 `agent_error`。清单支持搜索、分组、标签、启用状态、在线状态，以及 CPU/内存/磁盘/状态排序。只有从未注册的主机记录可以删除；禁用会保留历史和审计。

### 注册边界

Controller 签发短期令牌，生成的命令通过 `0600` 令牌文件传递。当前生产安装脚本仍需要预先签发的 mTLS 证书、私钥和 CA bundle 才能调用注册接口；目标主机上自动生成 CSR 并完成完整 bootstrap 的流程尚未实现。证书轮换和吊销仍由 Controller 管理。

## 指标和保留

Agent 采集 CPU/负载、内存和 Swap、所有可读取挂载点及 inode、网络计数、启动时间/运行时长、系统/内核/架构、Agent 版本、队列长度、Agent RSS/CPU 和重启次数。缺失值不会伪装为零。Controller 同时按时间和每主机/每检查行数限制保留数据。

## 服务检查、告警和通知

支持 HTTP/HTTPS、TCP、ICMP、Docker 和 systemd。HTTP 禁止凭据、查询字符串密钥、危险重定向和超大响应；内部地址必须显式 CIDR allowlist，DNS 结果在连接前校验。Docker/systemd 必须使用已登记主机和 Agent allowlist。ICMP 权限不足显示为 `unsupported`。告警状态、阈值、去重、静默、维护窗口、确认和恢复全部持久化。Telegram、SMTP、Webhook 只保存环境变量或受保护文件引用；默认测试仅允许本机 mock，真实外发必须显式开启部署开关。

## 修复和安装

修复闭环为“检测 -> 诊断 -> 建议 -> 审批 -> 签名任务 -> Agent 执行 -> 复检 -> 审计 -> 成功或升级”。只允许诊断、已登记 systemd/Docker 重启、清理预览、二次确认清理和 Restic backup/check；任意 Shell、重启主机、SSH、防火墙、DNS、Cloudflare、用户或全局 Docker 配置均不允许。仓库包含非 root systemd、SHA-256 校验、安装失败自动回滚和 `scripts/uninstall-agent.sh`。没有 Docker 的 Windows 环境不能伪报干净 Compose 安装成功。
