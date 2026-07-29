# 端口流量故障排查

| 现象 | 只读检查 | 安全处理 |
|---|---|---|
| 没有样本 | Agent `port_traffic_collection_error`、socket 状态、helper 日志 | 恢复 socket/helper；不得写入 0 用量 |
| 规则 `missing` | `nft -j list table inet vps_guardian_port_traffic`、策略/运行状态 | 重新应用监控策略并记录不连续 |
| 计数下降 | generation 和上一个原始样本 | 作为 wrap/reset，不计算负差值 |
| 配额告警不恢复 | 当前周期字节、规则状态、2% 迟滞 | 等待低于恢复线的两个成功样本 |
| 限速被拒绝 | `tc -j qdisc show dev <接口>` | 保留非 Guardian qdisc，重新设计隔离测试 |
| helper 拒绝请求 | systemd 日志、Agent 任务结果 | 修正结构化策略，禁止用 Shell 绕过 |
| 升级失败 | 安装备份与 SHA256SUMS | 从准确备份恢复二进制/unit |

不得通过 flush 整台主机防火墙、删除全部 qdisc、重建 Agent 身份、修改 DNS/代理或
重装节点来修复。只保存脱敏命令，不附加未脱敏主机导出。

缺失点代表未知，不代表 0；重置是 generation 边界，不是流量丢失；规则恢复后，
`rule_missing` 区间仍保留。
