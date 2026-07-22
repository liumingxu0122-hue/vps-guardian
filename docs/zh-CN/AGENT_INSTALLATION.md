# Agent 安装

[English](../en/AGENT_INSTALLATION.md) | [简体中文](AGENT_INSTALLATION.md)

先在 Dashboard 创建主机记录，再生成该主机的短期注册包。通过受保护通道传输固定版本的 Agent 二进制、校验和、Controller 公钥、服务器 CA，以及权限为 `0600` 的注册 Token 文件。禁止把 Token 放入命令参数或长期配置。

以 root 身份执行生成的 `scripts/install-agent.sh` 命令。安装器会校验二进制和服务器 CA，在 Agent 主机本地生成 P-256 TLS 私钥、CSR 和 Ed25519 签名私钥，再通过 Agent Gateway 提交 CSR。私钥永远不会离开 Agent 主机。请求完成后 Token 文件会被删除，而且不能重复使用。

身份文件按代际保存在 `/etc/vps-guardian-agent/identities` 下，`current` 符号链接选择当前生效代际。密钥不允许其他用户读取；续签后保留上一代身份用于受控回滚。公开 CA 文件单独保存在 trust 目录。

Agent 只在配置的到期前窗口内续签。Controller 要求当前 mTLS 身份、签名请求、新 CSR、新 Ed25519 密钥持有证明和身份版本 CAS。切换前，Agent 会校验新证书与私钥、固定 CA、客户端认证用途、SPIFFE 身份、指纹和证书内实际有效期。续签失败会保留当前代际，并使用受限重试间隔。

证书吊销是受控操作员流程。先生成并验证单调递增的候选 CRL，使用 `scripts/publish-agent-crl.sh` 发布，确认 Agent Gateway 健康且旧证书已被拒绝，再通过授权 Controller API 记录对应身份吊销。Agent 身份维护不得执行 `forget`、`prune`、防火墙修改或任何非项目服务操作。

安装后必须验证心跳新鲜、Agent ID 和证书序列号独立、指标与服务结果正常、重启后仍能恢复且离线队列为空。撤销未使用的注册材料。严禁跨主机复用身份、关闭证书校验，或把密钥写入 Git、Shell 历史、日志、截图和支持包。
