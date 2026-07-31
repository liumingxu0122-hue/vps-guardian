# 端口流量安全模型

## 信任边界

Agent 继续以非 root 运行，保留 `NoNewPrivileges=yes`，不持有 capability。它只向
`/run/vps-guardian-net-helper/helper.sock` 发送一次有上限的 JSON 请求。socket
属主为 root，仅 `vps-guardian-agent` 组可读写，每个连接启动一个新的 root
oneshot 服务。

helper：

- 只接受 `snapshot`、`apply`、`remove`、`reset` 和 root 本地 `purge`；
- 校验全部字段、UUID、协议、方向、端口段、接口、配额、速率、generation 和策略上限；
- 不接受命令、可执行路径、URL、Token、Cookie、密钥或 Shell 字符串；
- 通过参数数组执行 `nft`/`tc`，nftables 规则只经 stdin 输入；
- 仅拥有 `inet vps_guardian_port_traffic` 表和 TC handle `7a11:`；
- 发现非 Guardian root qdisc 时拒绝限速；
- 无互联网地址族，仅获得 `CAP_NET_ADMIN`；
- 只能写 `/var/lib/vps-guardian-net-helper` 和 `/run/lock`。

unit 还启用了严格的文件系统、Home、临时目录、内核、control group、SUID/SGID、
personality、realtime 和可执行内存限制。首版评估了静态 `SystemCallFilter`，但不同
发行版的 `nft`/`tc` 系统调用面并不一致，因此暂不启用；固定可执行文件与参数、
地址族限制、capability 上限及隔离 Linux 门禁仍为强制项，待验证可移植 allowlist
后再收紧。

## 授权

Viewer 只能读取摘要和有上限历史。Admin/Owner 在 Step-up 后可创建或更新仅监控
策略。配额执行、手工重置、计划重置配置和 TC 限速必须经过高风险双人审批，请求
人和批准人不能相同。计划执行还要求已保存的申请与审批来源完整，否则失败关闭。
签名任务绑定动作、参数、审批、双方身份、目标主机、nonce 和 30–900 秒有效期；
helper 还会把签名目标与 root-only 本机 Agent 配置进行等值核对。无效、过期、重放、
自批、目标不匹配或未绑定主机的任务全部失败关闭。

## 原子性与回滚

重建 Guardian 规则前，helper 先把当前内核计数吸收到持久累计偏移。nftables
使用单一事务；随后应用 TC。TC 或状态提交失败时，会恢复之前的 Guardian nft/TC
状态和已吸收计数。无关防火墙表和 qdisc 不会被 flush。

helper 不是通用防火墙管理器。Controller 历史、重置事件和审计记录独立保留或只追加。

## 剩余风险

内核/工具版本兼容和恶意本地 root 不在此边界内。TC 与 nftables 无法组成单个内核
事务，因此使用补偿回滚。合并前必须在隔离 Linux Staging 验证。
