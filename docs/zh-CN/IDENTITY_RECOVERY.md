# 身份恢复闭环

本补丁目前仅存在于候选功能分支：未部署、未迁移在线数据库，也未修改任何线上
用户、密码、TOTP Secret、恢复码或 Session。

## 安全边界

- 只有已认证 Owner 可以创建另一个 Owner；管理 CLI 只能在空数据库中创建首个身份。
- Owner 创建的用户使用 Argon2id 保存初始密码，并设置
  `must_change_password=true`。首次设置完成前，后端只允许改密、TOTP 设置与确认、
  恢复码保存确认和退出登录。
- TOTP Secret 使用配置的 Fernet 密钥加密。设置 Secret 与恢复码只返回一次，禁止
  写入审计记录。
- 恢复码由密码学安全随机数生成，数据库只保存带服务端密钥的 SHA-256 摘要；使用时
  加锁并立即失效，重新生成批次会撤销全部旧码。
- JWT 同时绑定服务端 Session ID 与用户 `session_version`。每个认证请求都会重新检查
  用户存在且启用、当前角色与 scopes、版本、Session 是否撤销以及是否过期。
- 修改密码会增加版本、撤销其他 Session，并只重新签发明确保留的当前 Session。
  角色、scope、禁用、关闭 TOTP 和管理员重置密码都会使相关 Session 失效。
- 删除、禁用、降级或撤销全部 Session 前，后端会锁定活跃 Owner 行；如果操作会破坏
  最后 Owner 边界，则拒绝并写入审计。
- Session 的 IP 与 User-Agent 只保存带密钥摘要。审计不包含密码、密码哈希、TOTP
  Secret、完整恢复码、JWT、Cookie 或 CSRF Token。

## 威胁模型

| 威胁 | 服务端控制 | 剩余风险 |
| --- | --- | --- |
| JWT 被窃取 | Session 行、过期、撤销与版本校验 | 在被发现或过期前仍可能被使用 |
| 初始密码被滥用 | 每个请求都执行首次设置白名单 | 初始密码交付仍是运维责任 |
| TOTP 重放 | 只接受更大的时间步计数 | 多 Controller 实例需要数据库串行化 |
| 恢复码数据库泄露 | 只保存带密钥摘要且单次使用 | JWT 密钥同时泄露时可尝试离线验证 |
| 最后 Owner 竞态 | PostgreSQL `SELECT ... FOR UPDATE` | 仅用于测试的 SQLite 不具备同等行锁 |
| Secret 泄露 | 显式 DTO 与脱敏追加式审计 | 浏览器内存和剪贴板仍是端点风险 |

## 迁移与回滚申请

可逆迁移 `0010_identity_recovery` 位于 `0009_agent_provenance` 之后。未来申请
Staging 授权前必须：

1. 创建加密数据库备份并记录 SHA-256；
2. 恢复到隔离 PostgreSQL 副本；
3. 记录表行数、身份数据与审计完整性；
4. 执行 `alembic upgrade 0010_identity_recovery`；
5. 校验用户、审计、恢复码哈希与 Session 一致性；
6. 执行 `alembic downgrade 0009_agent_provenance`，完成兼容性校验后再次升级；
7. 单独申请变更窗口和回滚授权。

未经明确授权，不得对当前在线 Controller 执行上述步骤。Staging 部署为
`NO-GO`，Production 为 `NO-GO`。
