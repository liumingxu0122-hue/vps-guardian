# Agent 安装

[English](../en/AGENT_INSTALLATION.md) | [简体中文](AGENT_INSTALLATION.md)

先在 Dashboard 创建主机清单，再通过 Controller 的授权流程生成短期注册包。使用受保护通道传输，并在使用前校验哈希。

按架构安装明确版本的 `linux-amd64` 或 `linux-arm64` `guardian-agent`、root 所有的配置文件、CA 信任材料和 systemd 单元。私钥权限必须为 `0600`；配置及公开信任材料应归 root 所有，其他用户不得写入。

启动服务后，在 Dashboard 验证心跳新鲜、证书序列号符合预期、指标正常且离线队列为空。注册完成后撤销临时注册材料。禁止跨主机复用 Agent 身份、关闭证书验证，或把密钥写入 Git、Shell 历史、日志和支持包。

证书轮换和吊销由 Controller 管控。替换身份完成经过验证的心跳前，应保留上一组信任材料。
