# 哪吒基准计划与证据

本文定义 VPS Guardian 与隔离的哪吒 V1 部署之间的可复现实验。无法测量的项目明确记为 `Pending`，不使用虚构数字。

## 测试边界

对比必须使用同一台干净 Linux 主机、相同 CPU/内存/磁盘限制和网络路径，并使用相互独立的 Compose project、网络、卷、端口和临时凭据。不得触碰生产 Guardian、Sub2API、Komari、KobeHub 或其他服务。Dashboard/Agent 版本固定为 [NEZHA_STUDY.md](NEZHA_STUDY.md) 中的引用，Guardian 固定为待测 commit。

当前 Windows 工作站没有 Docker Engine，因此没有声称完成干净 Compose 安装、镜像构建或运行时基准。`.github/workflows/ci.yml` 的 `compose-and-images` job 仍是必需的 Linux 门禁。

## 测量项

| 测量项 | VPS Guardian | 哪吒 | 状态 / 方法 |
| --- | --- | --- | --- |
| 干净安装耗时 | Pending | Pending | 干净 Linux VM，记录命令开始/结束和拉取镜像耗时 |
| Agent 二进制大小 | Pending | Pending | 记录压缩包和安装后二进制大小 |
| Agent 空闲 CPU | Pending | Pending | 稳态 15 分钟，采集 cgroup 与主机计数器 |
| Agent 空闲 RSS | Pending | Pending | 稳态 15 分钟 RSS 与 cgroup 内存 |
| Agent 每分钟网络字节 | Pending | Pending | 相同心跳间隔且无主动检查 |
| 指标刷新延迟 | Pending | Pending | 采集、Controller 接收和界面可见三个时间戳 |
| 离线发现时间 | Pending | Pending | 阻断 Agent 网络，测量首次持久化离线状态 |
| HTTP/TCP 故障发现 | Pending | Pending | 相同目标和检查间隔 |
| 恢复通知耗时 | Pending | Pending | 本地 mock 接收器，包含重试/退避时间 |
| 重复告警数量 | Pending | Pending | 固定窗口内一次故障/恢复事件 |
| 误报 / 漏报 | Pending | Pending | 带预期状态转换的故障注入矩阵 |
| 24 小时数据增长 | Pending | Pending | 记录 24 小时前后数据库/数据卷字节数 |
| Controller/Dashboard CPU 与 RSS | Pending | Pending | 相同主机限制和等量 Agent |
| 升级耗时与回滚 | Pending | Pending | 固定旧/新版本并故意触发健康门禁失败 |
| 卸载耗时与残留 | Pending | Pending | 检查服务、文件、卷和历史/审计保留 |
| RBAC 与 Agent 身份检查 | Pending | Pending | 手工安全清单，不作为性能分数 |
| 远程任务安全检查 | Pending | Pending | 验证 allowlist、审批、nonce 和签名 |
| 审计完整性 | Pending | Pending | 对比请求、批准、执行和复核记录 |
| 备份/恢复验证 | Pending | Pending | 隔离 Restic/数据库恢复和关键记录校验 |

## 必测场景

1. 从干净快照安装两个系统，不修改生产 DNS 或防火墙。
2. 注册相同数量 Agent，采集相同基础指标 15 分钟。
3. 以相同间隔对本地 mock 目标执行 HTTP、TCP、ICMP 检查。
4. 注入 Agent 离线、目标故障、延迟响应和恢复，记录状态转换及通知重试。
5. 执行文档化备份和隔离恢复流程。
6. 执行升级，并故意让一个健康门禁失败，验证只回滚应用而不触碰依赖。
7. 删除测试部署，核对文档规定的残留和历史行为。

## 当前仓库门禁

Phase 4B 工作区已通过可用的本地代码门禁：Python 测试（247 passed、16 skipped）、Go 格式化/vet/测试、Web typecheck/单测/生产构建及现有 Playwright 视觉套件。这些是实现门禁，不是 Nezha 运行时基准。当前工作站因没有 Docker 而阻塞 Compose 验证，必须在 Linux CI 上完成后，才能声称干净安装或运行基准完成。

## 解释规则

- 不比较不同功能集或不同检查间隔。
- 延迟和资源采样报告 median、p95 和样本量。
- 原始测量应作为 CI artifact 保存，但必须脱敏。
- 跳过或不可用的测量保持 `Pending`，并阻止“基准已完成”的结论。
- 基准结果不授权生产部署，也不授权移动现有 release tag。
