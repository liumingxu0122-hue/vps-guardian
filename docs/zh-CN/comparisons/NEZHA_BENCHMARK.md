# 哪吒 2.3.0 隔离基准

[English](../../en/comparisons/NEZHA_BENCHMARK.md) | [简体中文](NEZHA_BENCHMARK.md)

本流程在相同条件下比较 VPS Guardian 与已经固定版本的哪吒 2.3.0 研究目标。当前全部运行时数值仍为 `Pending`；隔离部署和 24 小时采集都尚未通过预检。

## 隔离规则

使用相同的干净 Linux 容量、Agent 数量、心跳与检查间隔、故障目标和观察窗口。Compose project、网络、卷、服务名、本机高位端口和 root-only 凭据必须相互独立。禁止配置公网 DNS、反向代理、Docker socket、终端、远程命令、MCP 或生产资源。启动前必须设置 CPU、内存、磁盘和日志上限。

## 测量项目

| 测量项 | VPS Guardian | 哪吒 2.3.0 | 方法 / 状态 |
| --- | --- | --- | --- |
| Dashboard 安装耗时 | Pending | Pending | 干净快照，分开记录拉取与启动时间 |
| Agent 安装耗时和二进制大小 | Pending | Pending | 使用相同架构和传输路径 |
| Agent 空闲 CPU / RSS / 每分钟流量 | Pending | Pending | 预热 15 分钟后报告中位数、p95 和样本量 |
| 指标刷新延迟 | Pending | Pending | 记录采集、接收和 UI 时间戳 |
| 离线及 HTTP/TCP 故障发现 | Pending | Pending | 相同间隔、阈值和合成目标 |
| 恢复通知延迟 | Pending | Pending | 本地 mock 接收器并记录重试时间 |
| 重复、误报和漏报告警 | Pending | Pending | 固定预期状态转换矩阵 |
| 24 小时存储增长 | Pending | Pending | 真实 24 小时前后比较卷和数据库字节数 |
| Controller/Dashboard CPU 与 RSS | Pending | Pending | 相同 cgroup 上限和 Agent 数量 |
| 重启后状态一致性 | Pending | Pending | 对比持久化主机、告警和审计状态 |
| 升级、回滚和卸载残留 | Pending | Pending | 固定版本并故意触发一次健康门禁失败 |
| 身份、RBAC、任务、审批和审计 | Pending | Pending | 安全能力检查，不作为性能分数 |
| Restic/S3 灾难恢复 | Pending | 不等价 | 如实说明能力差异，不制造伪对等数据 |

## 解释规则

实测、推断、阻塞和 Pending 必须分别记录。缺失功能不得填写虚构性能值。实现结果较好也不能证明生产可用。24 小时项目只能在真实时间过去后完成；Guardian 的 7 天观察也必须在真实 7 天过去前保持 `Running/Pending`。
