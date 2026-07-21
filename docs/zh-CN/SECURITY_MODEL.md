# 安全模型

[English](../en/SECURITY_MODEL.md) | [简体中文](SECURITY_MODEL.md)

VPS Guardian 假设受管主机、网络、运维人员和外部存储可能独立故障或被攻陷。项目控制用于缩小影响范围，不能替代主机加固。

- TLS 1.3 与 mTLS 认证 Agent 入口；证书轮换和 CRL 检查限制过期身份。
- 签名任务、Nonce、有效期和重放检测把执行绑定到已授权请求。
- RBAC、TOTP、CSRF 防护、登录限流、审批和二次确认保护运维操作。
- 追加式审计记录操作者、动作、资源、来源和结果，不翻译原始证据。
- Secret 仅保留在服务端受限文件或 Secret Store 中，Web 构建产物不得包含 Secret。
- 备份凭据应限定到 Bucket，恢复必须隔离执行并验证。

请按照仓库 `SECURITY.md` 私下报告漏洞。Issue 中不得包含真实凭据、私钥、个人数据或生产证据。
