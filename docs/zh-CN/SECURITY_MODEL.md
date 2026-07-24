# 安全模型

[English](../en/SECURITY_MODEL.md) | [简体中文](SECURITY_MODEL.md)

VPS Guardian 假设受管主机、网络、运维人员和外部存储可能独立故障或被攻陷。项目控制用于缩小影响范围，不能替代主机加固。

- TLS 1.3 与 mTLS 认证 Agent 入口；证书轮换和 CRL 检查限制过期身份。
- 签名任务、Nonce、有效期和重放检测把执行绑定到已授权请求。
- RBAC、TOTP、CSRF 防护、登录限流、审批和二次确认保护运维操作。
- 追加式审计记录操作者、动作、资源、来源和结果，不翻译原始证据。
- Secret 仅保留在服务端受限文件或 Secret Store 中，Web 构建产物不得包含 Secret。
- 备份凭据应限定到 Bucket，恢复必须隔离执行并验证。

## 公开 Staging 边界

可选匿名 Staging 访问使用独立 Public API 命名空间和显式响应模型，不会授予 viewer 角色，
也不复用已认证的资产、快照、事故、修复、恢复、审计、Agent 身份、通知或设置响应。缺少
凭据的请求只能进入固定的方法与路径白名单。Bearer Token 或 `guardian_session` Cookie
存在时必须完成验证，失败后不得降级为匿名访问；偏好与其他普通 Cookie 不属于凭据。参见
[公开只读 Staging 面板](STAGING_PUBLIC_READ_ONLY.md)。

请按照仓库 `SECURITY.md` 私下报告漏洞。Issue 中不得包含真实凭据、私钥、个人数据或生产证据。
