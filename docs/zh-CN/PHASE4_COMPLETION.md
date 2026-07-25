# Phase 4 完成指南

Phase 4 的目标是在保留登录保护、Agent 信任边界、受限修复、灾备校验和轻量架构的前提下，
把 Developer Preview 推进为更完整的运维控制面。

## 本分支新增内容

- 面向决策的总览、独立“需要关注”队列、分组响应式导航、面包屑、命令面板、明暗主题和
  中英文资源；
- 版本、提交和部署来源，以及可解释的总体健康原因；
- 1h/24h/7d/30d 稳定性组成项、置信度、分组和地区聚合；
- 告警指派/关闭和带审计的事故状态流转；
- 通知事件范围、严重度过滤、投递记录、有限重试和死信；
- Owner/Admin/Operator/Viewer、显式收窄 Scope、密码轮换、Session 撤销、最后 Owner
  保护，以及 Owner 高风险变更再认证；
- 有上限的检查历史、结构化审批详情、Agent/安全/通知/设置页面、分页、请求取消接口和
  GET 请求去重；
- 可升级、可降级的 `0008_phase4_completion` 数据库迁移；
- 没有明确生产门禁和不可变提交时拒绝启动的生产配置。

这些是代码能力，不代表真实 Staging 或生产门禁已经通过。

## 架构与信任边界

浏览器通过需要登录的 Web/Controller 入口访问。Agent 使用独立的 TLS 1.3 mTLS Gateway。
Agent 私钥只留在 Agent 本地；Controller 只签发主机绑定 CSR。签名任务、Nonce 防重放、
固定修复动作、风险审批和只追加审计共同限制远程操作范围。

PostgreSQL 保存运维状态。备份任务使用受保护的文件型凭据和站外 Restic 仓库；只有完成
隔离恢复和应用校验后，恢复点才能标为已验证。

参见[架构](ARCHITECTURE.md)、[安全模型](SECURITY_MODEL.md)、
[Phase 4 威胁模型](../phase4/security-threat-model.md)和
[备份恢复](BACKUP_AND_RESTORE.md)。

## RBAC

- Viewer：只读。
- Operator：执行日常受限操作，不能管理高权限用户。
- Admin：可做 Owner 以下的管理，不能移除最后一个 Owner。
- Owner：最高角色上限；高风险账号变更必须输入当前密码再次认证。
- 显式 Scope：例如 `alerts:read`，只会进一步收窄权限，绝不会突破角色上限；读写分开。

Cookie Session 的写请求必须通过 CSRF。Bearer Token 仍需认证，但不使用 Cookie CSRF。
禁用用户、轮换密码或撤销 Session 都会递增 Session 版本，使旧 Session 失效。

## Agent 与证书生命周期

1. 创建或选择主机。
2. 签发短期、单次、主机绑定的注册 Token。
3. Agent 在本地生成私钥并提交 CSR。
4. Controller 校验身份并签发仅用于客户端的证书。
5. Gateway 在 TLS 边界校验 CA、SAN/身份、有效期和 CRL。
6. 续签使用当前身份证明并原子切换身份代际。
7. 吊销时发布单调递增 CRL，并退役旧身份。

系统不展示永久私钥，也不把 Agent 私钥发给 Controller。重装不得静默替换已有身份。
真实 CRL 握手拦截与完整轮换仍是 Phase 3 门禁。

参见 [Agent 安装](AGENT_INSTALLATION.md)和 [Phase 4C](PHASE4C.md)。

## 告警、事故、修复和审批闭环

告警状态为 Firing、Acknowledged、Silenced、Recovered、Closed，并保存负责人和通知上下文。
事故流程为：

```text
Open → Acknowledged → Investigating → Mitigating → Resolved
```

每次流转都写审计；解决时可填写总结和复盘。

修复流程保持：

```text
申请 → 风险评估 → Dry Run → 审批 → 执行 → 验证 → 必要时回滚 → 审计
```

只允许注册动作：重启指定服务/容器/Agent、清理预定义缓存、轮换预定义日志、执行预定义
健康或 Restic 检查、安全重新采集。任意 Shell、SSH/防火墙/系统用户/代理配置/订阅和
任意删除都不在产品边界内。

## 通知

Telegram、Email、Discord、Webhook 通道带事件范围、严重度、重试和 Secret 引用元数据。
有限尝试后进入成功或死信，失败会出现在总览和“需要关注”。真实门禁要求至少两个外部
通道跑完整事件闭环，只发送测试消息不能算通过。

## Staging、回滚、磁盘和 Komari

执行时使用 [Staging/回滚 Runbook](../operations/phase4-staging-runbook.md)。Staging 必须
继续登录。分批观察 Guardian 时保留并且不修改 Komari。当前磁盘证据不支持执行运行时
数据迁移。

## 观察与生产

参见[观察计划](../phase4/observation-run.md)、
[稳定性公式](../phase4/stability-score.md)和
[生产门禁](../phase4/production-gate.md)。现有基线不能证明连续七天。生产结论为
**NO-GO**。
