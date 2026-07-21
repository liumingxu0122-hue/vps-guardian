# 哪吒监控研究

本文只研究官方哪吒 V1 仓库与文档中的架构和运维取舍，不复制源码，也不在 VPS Guardian 中使用哪吒品牌、Logo 或资源。

## 证据快照

研究时间为 2026-07-22，引用以下不可变参考：

| 组件 | 参考 | 解析后的 commit | Release |
| --- | --- | --- | --- |
| Dashboard | `nezhahq/nezha` 标签 `v2.3.0`（annotated tag `e84c0fcb172ddacc5b78ed7987b0c34406f898c2`） | `5d7e8b58af927abd9a1e7381c1269c9f2256eae1` | [v2.3.0](https://github.com/nezhahq/nezha/releases/tag/v2.3.0)，2026-07-21 发布 |
| Agent | `nezhahq/agent` 标签 `v2.3.0`（annotated tag `8db0e95c912c8636a8ae6600857b468012b64a8a`） | `84e61fca84661503d324ae6ab00ca88e280e00a2` | [v2.3.0](https://github.com/nezhahq/agent/releases/tag/v2.3.0)，2026-07-21 发布 |

官方 Dashboard 镜像为 `ghcr.io/nezhahq/nezha:v2.3.0`。GHCR OCI index digest 为 `sha256:afd4058d06e2eec8da38ee3c159a6aae4ffeb3b8b8dcb02dbdc303b547aef76d`，Linux/amd64 manifest digest 为 `sha256:dd923b4c7f8722e7708ae8088db6c59f4abf99704b03e129e91a82f401ff7167`。这些是公开 manifest 的观测值，不表示本 Windows 工作区已经运行该镜像。

官方 `nezha-agent_linux_amd64.zip` 的 SHA-256 为 `48353ada5e74ecaffb698d020e706376023837a9fc8e4c01fbb7f5e5893f32f5`，来源为 Release 的 `checksums.txt`。

## 架构与部署

哪吒 V1 由 Go Dashboard 和 Go Agent 组成。Dashboard 提供 Web 界面并通过 Agent 对接地址接收遥测。官方安装文档建议在使用 CDN 时为公开访问准备一个域名、为 Agent 通信准备一个不经过 CDN 的域名；防火墙放行 Agent 端口和 WebSocket 支持是运行前提。官方 Docker 构建使用包含平台专用 Dashboard 二进制的轻量 BusyBox 镜像，将 `/dashboard/data` 作为持久卷并暴露 8008 端口。

Agent 是按平台发布的二进制，可由 systemd 或其他服务管理器运行。配置包括 Dashboard 地址、客户端密钥/身份、UUID、TLS、更新周期和可选探针。官方安装脚本带交互和下载步骤；VPS Guardian 不采用未经校验的 `curl | sh` 流程。

## 注册与通信

哪吒使用 Dashboard 发放的客户端密钥和 Agent UUID。Agent 保持长连接并上报指标，Dashboard 也可以向在线 Agent 推送任务。CDN 的 WebSocket 行为不确定时，应让通信域名绕过 CDN。这种模型简单实用，但密钥保护和二进制信任链仍由部署方负责。

VPS Guardian 使用每主机注册记录、一次性 token 摘要、每设备 mTLS 身份、证书吊销/轮换和 Ed25519 签名任务。当前安装脚本通过受保护文件接收短期注册 token，但仍需要预先签发的证书、私钥和 CA bundle；完整 CSR bootstrap 接口尚未实现。这是 Phase 4B 的明确限制，不能描述为“全自动注册”已完成。

## 指标与历史

哪吒公开说明支持实时状态、流量、负载、CPU、内存、Swap、磁盘、进程和连接数，以及网络延迟历史图表。服务文档说明支持 1、7、30 天延迟视图，访客只能查看最短周期。Dashboard 通过自身存储配置保留时间序列数据。

VPS Guardian 采集 CPU/负载、内存/Swap、所有可读挂载点及 inode、网络计数器、启动时间/运行时长、操作系统、内核、架构、Agent 版本、队列长度、Agent RSS/CPU 和重启次数。缺失值保留明确状态，不强行填 0；Controller 同时按时间和每主机/每检查项行数限制保留量，使过期或不完整遥测可见。

## 服务检查

哪吒服务监控支持 HTTP GET（包含 TLS 证书检查）、TCPing 和 ICMP Ping，可按覆盖规则或指定 Agent 执行，并提供延迟图表；失败和延迟通知还可以触发任务。

VPS Guardian 增加 HTTP 响应断言、TLS 主机名/到期检查、响应体大小限制、TCP/ICMP 探针，以及 Agent 侧 Docker/systemd 检查。Controller 在连接前校验 DNS 结果，拒绝目标中的凭据和查询参数密钥，默认阻止私网、回环、链路本地和 metadata 网络；内部目标必须显式 CIDR allowlist。ICMP 权限不足显示为 `unsupported`，不会误判整台主机离线。

## 告警与迟滞

哪吒通知规则可以持续触发，也可以只在状态变化时触发，并能在故障或恢复时执行任务。官方文档覆盖主机资源、流量、延迟和服务失败通知。

VPS Guardian 将告警实例和转换记录持久化到 PostgreSQL。状态包含 `ok`、`pending`、`firing`、`acknowledged`、`silenced` 和 `resolved`，支持失败/恢复阈值、重复间隔、维护窗口、静默、确认、去重和 Controller 重启后恢复。稳定 fingerprint 用于投递去重，恢复通知可单独开启。

## 通知

哪吒支持通知方式、占位符、TLS 校验以及 Telegram、邮件、Webhook 等集成，文档定义 `Always` 和 `Once` 触发模式及可选任务执行。

VPS Guardian 只保存 Telegram、SMTP、Webhook 的环境变量或受保护文件引用。测试投递仅允许本地 mock，除非显式开启外部投递配置。投递尝试、响应码、重试状态、限速和仅类型错误摘要会被记录，不保存密钥。

## 任务与修复安全

哪吒支持计划任务、触发任务、覆盖规则、立即执行和 Shell/Batch 命令。这种能力很强，因此 Dashboard 凭据、Agent 密钥和任务授权必须由部署方严格保护。

VPS Guardian 第一批修复动作限制为诊断、allowlist systemd/容器重启、磁盘清理预览加二次确认，以及 Restic backup/check。任务绑定请求人、批准人、目标主机、action ID、参数、nonce、过期时间和 Ed25519 签名；高风险请求人不能批准自己的任务。任意 Shell、重启主机、SSH、防火墙、DNS、Cloudflare、用户和全局 Docker 配置均不注册为动作。

## 存储、升级与卸载

哪吒 Dashboard 镜像将数据保存到 `/dashboard/data`；官方 Release 流程发布多平台二进制和 GHCR 镜像。Agent Release 为各平台提供校验和，并说明内置或服务管理器重启方式。生产使用前仍应按目标版本复核官方备份、迁移和卸载脚本。

VPS Guardian 将 Controller 状态保存于 PostgreSQL，使用有上限的保留策略，并通过 Restic backup/check 和隔离恢复校验提供备份能力。安装脚本校验 SHA-256，以非 root systemd 用户运行 Agent，保留失败回滚副本；独立卸载脚本默认保留 Controller 历史和本地状态，只有显式 purge 参数才删除。

## 许可证与复用边界

Dashboard 和 Agent 仓库采用 Apache-2.0。若复制代码，必须保留 Apache 许可证、版权声明及适用的 NOTICE，并在修改文件中声明变更。本项目只研究接口和运维取舍，不复制哪吒源码、Logo、截图、主题或品牌。

## VPS Guardian 的结论

哪吒适合作为 Agent 覆盖规则、服务延迟历史、通知触发任务和轻量自托管部署的参考。VPS Guardian 借鉴这些思路，同时保留更严格的身份隔离、SSRF 防护、审批/签名链、持久化告警转换和 secret 引用策略。资源和运行时结论以 `NEZHA_BENCHMARK.md` 的隔离基准为准。

### 官方来源

- [哪吒 Dashboard 仓库](https://github.com/nezhahq/nezha)
- [哪吒 Agent 仓库](https://github.com/nezhahq/agent)
- [Dashboard 安装文档](https://nezha.wiki/guide/dashboard.html)
- [Agent 安装文档](https://nezha.wiki/guide/agent.html)
- [服务监控文档](https://nezha.wiki/guide/services.html)
- [通知文档](https://nezha.wiki/guide/notifications.html)
- [任务文档](https://nezha.wiki/guide/tasks.html)
