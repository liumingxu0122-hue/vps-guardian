# 身份恢复闭环

RC6 将浏览器 JWT 持久化替换为服务端不透明会话。在独立授权的 Staging 门禁完成前，
本候选版本仍仅存在于代码中；Production 保持 `NO-GO`。

## 安全边界

- 只有已认证 Owner 可以创建另一个 Owner；管理 CLI 只能在空数据库中创建首个身份。
- Owner 创建的用户使用 Argon2id 保存初始密码，并设置
  `must_change_password=true`。首次设置完成前，后端只允许改密、TOTP 设置与确认、
  恢复码保存确认和退出登录。
- TOTP Secret 使用配置的 Fernet 密钥加密。设置 Secret 与恢复码只返回一次，禁止
  写入审计记录。
- 恢复码由密码学安全随机数生成，数据库只保存带服务端密钥的 SHA-256 摘要；使用时
  加锁并立即失效，重新生成批次会撤销全部旧码。
- 浏览器 Cookie 只包含 384-bit 不透明随机 Secret。数据库仅保存其 SHA-256 哈希、
  独立绑定的 CSRF Secret 哈希、隐私化设备/IP 摘要、闲置期限、绝对期限、最近活动、
  Session 版本和撤销状态。API Bearer JWT 仍是独立的非浏览器认证路径。
- 标准浏览器会话采用 12 小时闲置期限和 7 天绝对期限；“在此设备上保持登录”采用
  7 天闲置期限和 30 天绝对期限。用户活动只能延长闲置期限，绝不能突破绝对期限，
  且数据库最多每 5 分钟写入一次活动。
- Cookie 写请求必须同时通过严格同源 `Origin`、可读 CSRF Cookie、相同请求 Header
  和服务端绑定哈希校验。显式携带的无效 Bearer Token 会直接被拒绝，不会降级使用
  有效浏览器 Cookie。
- 浏览器执行敏感操作前必须用密码加 TOTP 完成 step-up；结果只在当前会话内生效，
  最长 10 分钟，不会传播给其他设备或 API Token。
- 修改密码会增加版本、撤销其他 Session，并只重新签发明确保留的当前 Session。
  角色、scope、禁用、关闭 TOTP 和管理员重置密码都会使相关 Session 失效。
- 删除、禁用、降级或撤销全部 Session 前，后端会锁定活跃 Owner 行；如果操作会破坏
  最后 Owner 边界，则拒绝并写入审计。
- Session 的 IP 与 User-Agent 只保存带密钥摘要。审计不包含密码、密码哈希、TOTP
  Secret、完整恢复码、JWT、Cookie 或 CSRF Token。

## 威胁模型

| 威胁 | 服务端控制 | 剩余风险 |
| --- | --- | --- |
| 浏览器 Cookie 被窃取 | 仅哈希 Session 行、闲置/绝对期限、撤销与版本校验 | 活跃 Cookie 在过期或撤销前仍可能被使用 |
| CSRF | 严格同源校验、双提交 Token 与 Session 行绑定 | 同源脚本被攻陷后仍可使用用户权限 |
| 初始密码被滥用 | 每个请求都执行首次设置白名单 | 初始密码交付仍是运维责任 |
| TOTP 重放 | 只接受更大的时间步计数 | 多 Controller 实例需要数据库串行化 |
| 恢复码数据库泄露 | 只保存带密钥摘要且单次使用 | JWT 密钥同时泄露时可尝试离线验证 |
| 最后 Owner 竞态 | PostgreSQL `SELECT ... FOR UPDATE` | 仅用于测试的 SQLite 不具备同等行锁 |
| Secret 泄露 | 显式 DTO 与脱敏追加式审计 | 浏览器内存和剪贴板仍是端点风险 |

## 迁移与回滚申请

可逆迁移 `0012_persistent_sessions` 位于 `0011_dashboard_query_indexes` 之后。
申请 Staging 授权前必须：

1. 创建加密数据库备份并记录 SHA-256；
2. 恢复到隔离 PostgreSQL 副本；
3. 记录表行数、身份数据与审计完整性；
4. 执行 `alembic upgrade 0012_persistent_sessions`；
5. 校验用户、审计、恢复码哈希与 Session 一致性；
6. 执行 `alembic downgrade 0011_dashboard_query_indexes`，完成兼容性校验后再次升级；
7. 单独申请变更窗口和回滚授权。

未经明确授权，不得对当前在线 Controller 执行上述步骤。Staging 部署为
`NO-GO`，Production 为 `NO-GO`。
