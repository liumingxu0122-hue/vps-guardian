# Phase 4C Staging 真实验收

[English](../en/PHASE4C.md) | [简体中文](PHASE4C.md)

Phase 4C 新增基于 CSR 的 Agent Bootstrap、受限证书续签、受控 CRL 发布和双主机真实 staging 验收。本阶段不授权生产部署；哪吒 2.3.0 隔离对比仍是独立的 Pending 基准。

## 当前状态

| 门禁 | 状态 | 证据边界 |
| --- | --- | --- |
| CSR Bootstrap 实现 | 通过 | 两台真实 staging 主机分别消费主机绑定的一次性 Token |
| Token 消费 | 通过 | 两个 Token 均只消费一次；认证重放返回 401；无可用 Token 残留 |
| Agent 证书续签 | 通过 | 新私钥保留在本机，身份代际完成原子切换 |
| CRL 生成 | 通过 | 签名 CRL 单调递增、保留历史吊销项，并由 Gateway 工作流加载 |
| HAProxy CRL 拦截 | 通过 | 旧证书被拒绝，新证书能够到达 Controller |
| Staging 部署 | 通过 | 四个项目容器 healthy、RestartCount 0；非项目服务与接受基线一致 |
| Staging 通过 CSR 接入的 Agent | 2 | 活跃证书序列号不同、心跳新鲜、非 root systemd 运行、活跃任务积压为 0 |
| 服务与告警流程 | 通过 | 八项 Docker/systemd/HTTP/TCP 检查；完成 firing、确认、静默、本机投递和恢复验证 |
| 审批修复流程 | 通过 | 请求与审批职责分离，签名任务、受限清理、postcheck、重放幂等和 TTL 拒绝均通过 |
| 哪吒 2.3.0 隔离部署 | Pending | 尚未宣称任何运行时对比结果 |
| 24 小时采集 | 未启动 | 仅在两个隔离部署都通过预检后启动 |
| 7 天观察 | Pending | 必须等待真实 7 天后才能验收 |

## CSR Bootstrap 边界

授权操作员先创建主机，再签发短期注册 Token。Controller 只保存 Token 的 SHA-256 摘要。安装器从权限为 `0600` 的文件读取 Token，在 Agent 主机本地生成 TLS 私钥和 Ed25519 签名私钥，经私有 Agent Gateway 提交 CSR，并在使用后删除 Token 文件。Token 绑定目标主机，可撤销、受速率限制，并以原子方式只消费一次。

只有精确的 Bootstrap 路径可以在没有客户端证书时进入 Agent Gateway；其他 Agent 路径全部要求 TLS 1.3 客户端证书。生产环境中的 Controller 还会校验网关私有认证头，因此不能通过 Web 反向代理绕过该边界。

## 续签与吊销

Agent 仅在证书到期前的受限窗口内续签。续签请求同时使用当前 mTLS 身份和 Ed25519 请求签名认证，并包含新签名密钥的持有证明。Controller 使用身份版本 CAS。Agent 会先用固定 Agent CA 校验证书链，并核对私钥、预期 SPIFFE URI、指纹和证书内实际有效期，之后才原子切换 `identities/current` 链接；旧代际继续保留用于回滚。

CRL 发布由主机侧受控执行。`guardian-admin build-agent-crl` 从序列号文件和受保护 CA 文件生成候选 CRL。`scripts/publish-agent-crl.sh` 先校验候选和 HAProxy 配置，再原子替换 CRL，并且只重建 Agent Gateway；健康检查失败时恢复旧 CRL。发布 CRL 和记录对应的 Controller 身份吊销都是带审计的操作员动作。

## Staging 验收流程

首次写入前，每个目标都必须通过磁盘、inode、I/O、回滚镜像、数据库备份、SSH 回滚入口、项目容器和非项目服务基线检查。随后至少用两台真实 staging 主机验证独立证书序列号、新鲜指标、服务检查、告警迟滞、通知重试、审批职责分离、签名任务、Nonce 防重放和完整审计。

故障注入只能作用于 VPS Guardian 或专用合成服务。严禁填满根盘、停止 SSH、重启整机、修改全局防火墙、触碰生产或修改非项目服务。

## 观察结论

当前生产结论仍为 **NO-GO**。Phase 4C 仍属于 Alpha 验证。双主机 staging、本机通知、证书生命周期和审批修复门禁已通过，但不能替代长周期观察、外部通知投递、隔离对比或生产就绪评审。
