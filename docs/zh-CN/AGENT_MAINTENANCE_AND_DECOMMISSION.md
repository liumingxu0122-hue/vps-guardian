# Agent 修复、重装、身份轮换与退役

本流程只作用于已有 Host 和 Agent，不创建第二个 Host，并保留指标、告警、
检查、任务、审计历史和 Host 记录。本文不授权执行 Staging 或 Production。

## 授权与凭据

- Viewer/Auditor 只能查看状态。
- Operator 只能签发 `repair`。
- Admin/Owner 可签发修复、重装和身份轮换；存在
  `group:<name>:maintain` 时必须满足分组范围。
- 退役还要求当前 Step-up、与 Host 绑定且申请人与批准人分离的
  `agent.decommission` 批准、勾选确认和准确输入 Host 名称。
- 批准本身不会自动执行。

注册、维护、进度和退役凭据相互独立。凭据与 Host 绑定，Controller 只保存
哈希，可选绑定来源 CIDR，只能使用一次，最长 10 分钟有效。不同类型不能
互换。明文只在首次响应中出现，关闭浏览器对话框后立即清除。

## 发布物校验

HTTPS 和 Controller 固定的 SHA-256 继续强制执行。在信任清单内任何校验和
之前，脚本必须先使用独立固定公钥的 SHA-256，验证带版本绑定的安装清单
Ed25519 分离签名。错误公钥、签名、清单、版本、架构校验和或制品都会失败
关闭，不存在跳过参数。

CI 在上传目录外创建短期测试签名私钥，验证成功与篡改用例后销毁私钥。
Public Alpha 使用 `release/keys/` 中经过审查的公钥和 Key ID；对应私钥始终
保存在 Git 之外，仅密钥保管人可读。这把 Alpha 密钥不是离线 Production
签名密钥，也不构成 Production 授权。

## 修复与重装状态机

1. 通过当前 mTLS 消费一次性会话；
2. 验证签名清单和固定制品；
3. 备份现有二进制、配置、身份链接和服务状态；
4. 只停止 `vps-guardian-agent`；
5. 安装候选二进制；
6. 重装/轮换时在本机生成新密钥和 CSR，并用身份版本 CAS 原子切换代际；
7. 重启 Agent，等待 Controller 实际观察到变更后的心跳；
8. 旧身份保持 `retiring`；
9. 发布并验证匹配 CRL、撤销旧身份后才允许最终完成。

失败时只恢复 Agent 二进制、配置、身份链接和原服务状态。网络中断会留下
可审计的未完成或已回滚状态；重启不会把未完成会话变成成功。

## 退役

命令以当前 mTLS 和退役专用 Token 启动，停止 Agent，只删除 Agent 服务、
二进制和配置，再用受限进度凭据报告 `confirmation_pending`。默认保留
`/var/lib/vps-guardian-agent`；清除模式也只删除这个精确目录。

Controller 最终确认必须具有匹配的 CRL 发布证据，随后撤销证书身份、取消
待执行 Agent 任务、禁用 Host，并保留所有 Controller 历史。网络失败保持
`confirmation_pending` 或 `failed`，不得显示为完成。强制撤销仍属于独立
批准和审计的运维动作。

## 发行版证据与剩余 Staging 门禁

CI 在 amd64/arm64 的 Ubuntu 24.04、Debian 12、Rocky 9、Alpine 3.21
容器中执行文件系统、脚本、平台、信号清理和签名契约。容器不会伪造
systemd/OpenRC。真实服务管理器、mTLS 入口、心跳、CRL 拒绝、断网回滚和
无关文件不变性，仍须在两台明确授权的 Staging VPS 上验收。

## PR #9 Staging 验收状态

自动化检查已经覆盖并通过：注册与维护凭据隔离、单次使用/过期/防重放、
审批职责分离、CRL 发布门禁、信号清理、回滚边界和退役路径限制。

固定提交 `2122fa7fa91ed26e477a1e5cdf61262d2d1f0fde` 已在真实 Staging
通过一条命令注册、Agent 本地生成私钥与 CSR、首次 mTLS 心跳、Repair、
保留 Host 与历史的 Reinstall、身份轮换、CRL 发布，以及在 TLS 层拒绝旧证书。

真实双人 Decommission preserve/purge 标记为 **PENDING HUMAN ACCEPTANCE**。
该验收必须由两名独立控制人员和账号完成，自动化不得模拟职责分离。
本轮也未覆盖 Agent B/OpenRC 和 KVM 整机重启。这些剩余门禁不是代码测试
失败，也不构成 Production 授权；Production 继续为 **NO-GO**。
