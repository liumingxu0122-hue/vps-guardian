# Agent 一条命令注册

[English](../en/ONE_COMMAND_AGENT_ENROLLMENT.md) | [简体中文](ONE_COMMAND_AGENT_ENROLLMENT.md)

## 范围与发布门禁

本流程在 **主机 → 添加服务器** 中登记服务器，然后为目标 Linux 主机生成一条命令。功能默认关闭。只有配置固定发布版本、无凭据 HTTPS 资源地址、Ed25519 分离清单签名、独立固定的发布公钥 SHA-256，以及安装器、两种 Agent 架构、Controller CA 和 Controller 签名公钥的精确 SHA-256 后才可启用；缺失或占位值会失败关闭。

支持 `amd64`、`arm64` 的 Ubuntu、Debian、Rocky Linux、AlmaLinux、RHEL、Fedora 和 Alpine。`generic` 仅供操作员明确选择其他使用 systemd 或 OpenRC 的 Linux，不代表自动兼容。

本文不构成 Production 部署授权。Production 仍受现有发布和观察门禁约束。

## 支持的发行版

| 页面选择 | 接受的 `/etc/os-release` ID | 服务管理器 |
| --- | --- | --- |
| 自动检测 | Ubuntu、Debian、Rocky、AlmaLinux、RHEL、Fedora、Alpine | systemd 或 OpenRC |
| Debian | Ubuntu、Debian | systemd |
| RHEL | Rocky、AlmaLinux、RHEL | systemd |
| Fedora | Fedora | systemd |
| Alpine | Alpine | OpenRC |
| Generic | 人工确认后的任意非空 Linux ID | systemd 或 OpenRC |

## 安全模型

Admin 或 Owner 创建 Host；Operator、Admin 或 Owner 可创建该 Host 的 10 分钟注册会话，只有 Admin/Owner 可以撤销，且带分组范围的 Admin 只能管理授权分组。可选来源 CIDR 可把命令使用范围限制为目标服务器地址。重新生成命令会立即撤销上一条未使用会话。

命令包含一个短时注册凭据，浏览器只显示一次；Controller 只保存 SHA-256 摘要。凭据通过请求 Header 发送，不进入 URL。Controller 接受与 Host 绑定的有效 CSR 后，该凭据不能再次使用。随后使用一个独立限权的进度凭据，只能报告 `service_installed`、`service_started` 或安全失败信息；它同样只保存摘要、与会话同时过期、不能创建身份，安装结束后即删除。

Agent 在本机生成 P-256 TLS 私钥、CSR 和 Ed25519 请求签名私钥。Controller 只返回已签客户端证书、Agent CA 链、Gateway 地址和受限进度凭据。Agent 在原子写入新身份目录前，会校验证书与本地私钥、CA、客户端认证用途、SPIFFE Agent ID、Host 绑定、有效期，以及无凭据的 HTTPS Gateway。

安装器保证：

- 只下载固定版本，不解析 `latest`；
- 所有资源在执行或安装前均校验；
- 所有携带注册凭据的请求均拒绝重定向；
- 拒绝 URL 凭据、查询参数、Fragment、不安全 TLS、不支持架构和系统不匹配；
- 服务使用 `vps-guardian-agent` 非 root 用户，Capability 边界为空；
- 私钥权限为 `0600`；
- 支持 systemd 与 OpenRC，并使用失败重启策略；
- 只修改 VPS Guardian Agent 文件、本次新建的用户/组和 Agent 服务定义；
- 不修改 SSH、防火墙、SELinux、无关软件包、无关服务、Komari、DNS、CRL 或 Controller 凭据。

### 威胁与控制

| 威胁 | 控制 | 剩余风险 |
| --- | --- | --- |
| 命令复制到错误主机 | Host 绑定、10 分钟过期、可选来源 CIDR、立即撤销/重生成 | 允许来源若先使用泄漏命令，仍可能抢先注册 |
| Token 经 URL 或日志泄漏 | Header 传输、只存摘要、安全错误、审计不含 Token | 一条命令可能保留在目标机 Shell 历史 |
| 安装包被替换 | 无凭据 HTTPS、固定版本、独立固定的 Ed25519 清单签名，然后校验精确 SHA-256 | 离线正式发布私钥配置前，正式发布授权保持 BLOCKED |
| Controller 被冒充 | 固定 Controller CA、TLS 1.3 | CA 泄漏仍属于根信任事件 |
| 私钥外泄 | 本机生成、原子 `0600` 文件、非 root 服务 | Agent 主机 root 仍可读取 |
| 安装中断 | 变更前备份、哈希清单、服务状态记录、失败 Trap、限定范围回滚 | 断电可能中断回滚，需保留备份目录 |
| 跨租户注册 | Host 仅 Admin/Owner 可创建；Operator+ 可签发，Admin+ 可撤销，并可用 `group:<group>:enroll` 收窄 Admin | Host 分组正确性仍由操作员负责 |
| 伪造来源地址 | 仅在私有 Gateway 认证 Header 有效时信任转发来源 | Gateway Secret 泄漏会破坏此保证 |

## 操作流程

1. 发布固定版本的安装器和 Agent 资源；使用离线发布私钥签署版本绑定清单，发布分离签名，并通过受控流程记录发布公钥和制品 SHA-256。
2. 配置 `GUARDIAN_AGENT_INSTALL_*` 与 Controller 信任资源；验证完成前保持 `GUARDIAN_ONE_COMMAND_INSTALL_ENABLED=false`。
3. 备份 Controller 数据库与配置，记录当前 schema 和镜像。
4. 在隔离环境验证迁移 `0013_agent_enrollment` 的升级和降级。
5. 只在隔离 Staging 启用。
6. 在“添加服务器”中填写名称、地区/分组、系统系列、可选来源 CIDR 和备注。
7. 把命令复制到目标服务器。关闭对话框后页面会清除命令。
8. 观察状态时间线直至 `completed`，确认新鲜认证心跳和唯一 Agent/证书身份。
9. 撤销未使用命令。`failed`、`expired` 或 `revoked` 状态应生成新命令，旧命令继续无效。

安装器预期改动路径：

```text
/usr/local/sbin/vps-guardian-agent
/etc/vps-guardian/agent/
/var/lib/vps-guardian/agent/
/var/log/vps-guardian/
/etc/systemd/system/vps-guardian-agent.service
# 或 /etc/init.d/vps-guardian-agent
/var/backups/vps-guardian-agent/
```

## 回滚

安装器在 `/var/backups/vps-guardian-agent/` 下创建唯一 root-only 目录，复制原项目文件与服务定义并生成 `SHA256SUMS`。失败时会停止候选服务，只恢复 Agent 范围文件和原服务启用/运行状态；只有本次创建的用户/组才会删除；若进度凭据仍有效，会报告不含 Secret 的失败步骤和回滚结果。

Controller 发布回滚是独立流程：

1. 关闭一条命令签发；
2. 撤销未使用注册会话；
3. 除非另行批准吊销，不改变已注册 Agent 证书；
4. 回滚 Web 与 Controller 到兼容镜像；
5. 仅在确认旧 Controller 不读取新增表/字段后降级 `0013_agent_enrollment`；
6. 验证登录、健康、现有 Agent 心跳和审计只追加约束。

本回滚不得修改 CRL、防火墙、Komari、DNS 或无关服务。

## 升级、修复、证书轮换与卸载

集成流程使用 `0014_agent_maintenance`，详见
[Agent 维护与退役](AGENT_MAINTENANCE_AND_DECOMMISSION.md)。

不得对在线 Agent 重用初次注册命令。二进制修复或升级必须保留现有身份目录，并使用单独批准的固定版本产物流程。证书替换继续使用既有双身份轮换 API；Host 转移分组不要求重新安装。

卸载前，先完成受控证书吊销和 CRL 发布流程，并验证旧身份已被拒绝；随后运行受版本控制的 `scripts/uninstall-agent.sh`。脚本只停止并删除 Agent 服务、二进制和 Agent 配置，先创建带校验和的 root-only 备份；除非明确选择 `--purge-local-state`，否则保留本地队列与状态。该本地脚本不会伪称已经完成 Controller 吊销，也不会删除 Controller 中的 Host 历史或审计记录。

若 Bootstrap 请求超时，不要盲目重放：Controller 可能已经消费一次性 Token。应先检查脱敏会话状态和 Agent 身份，再按需要吊销并重新生成。

## 手工安装兜底

一条命令功能关闭时，使用 [Agent 安装](AGENT_INSTALLATION.md) 中既有受保护手工注册流程。仍必须使用固定版本与校验和、本机生成私钥、每主机唯一证书、非 root 服务账户和安装后心跳验证。不得跳过 TLS 或复用身份材料。

## 故障排查

- **签发命令返回 503：** 固定资源地址/哈希不完整，或功能开关未启用。
- **命令已过期/撤销：** 生成新命令，不尝试恢复旧凭据。
- **来源被拒绝：** 检查 CIDR，并确认注册流量经过可信 Agent Gateway。
- **系统不匹配：** 选择检测到的发行版系列；`generic` 只能在人工兼容性审核后使用。
- **校验和/版本不符：** 立即停止；修正受控发布元数据，禁止跳过校验。
- **CSR/证书被拒绝：** 检查时间同步、固定 CA，并确认命令运行在目标 Host。
- **服务安装失败：** 只检查 VPS Guardian Agent 服务与 root-only 备份清单。状态时间线只显示安全步骤和回滚结果。
- **服务启动但无心跳：** 检查出站 DNS/HTTPS、时间同步和近期 Agent 日志，不自动修改防火墙或代理策略。
