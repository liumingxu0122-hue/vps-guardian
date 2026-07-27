# UI V3 Implementation Review

状态：本地真实组件 + 结构化 API fixture 内部评审通过；Staging After 待验收

## 缺陷对应关系

| 审计范围 | 处理结果 |
|---|---|
| NAV-01～13 | 重做 220px 分组导航、可持久折叠、统一图标、可见选中项、`aria-current`、帮助/账户整合、低高度独立滚动和手机 Drawer。原文字消失根因是浅色主题仍继承近白文字；V3 选中态使用独立 Token。 |
| SVC-01～15 | 卡片墙改为表格/手机字段列表；产品名优先、ID 次级；状态/主机/类型/分组/排序/密度/分页与 URL 筛选；成功率、延迟、失败数和最近结果同层；批量启停/周期更新走受审计 PATCH。 |
| SVC-16～30 | Agent 输出先做语义分类和计数；原始证据默认关闭；systemd 空失败集合为 Healthy；区分 execution failed、object issue、no data、unsupported、parse failed；证据支持格式化、换行、全屏、复制和脱敏下载。 |
| INC-01～27 | 黑色选中行改为轻 Accent；列表增加影响、Owner、来源、创建/持续/更新和下一步；详情 Drawer 增加决策、时间线和证据计数；测试/S5 记录明确标记并不驱动 Bootstrap 严重健康。 |
| OVR-01～10 | 首屏收敛为 5 个 Summary、最多 5 条 Attention、独立当前资源、可恢复性和明确 Gate blocker；不显示 SHA 或裸 Snapshot ID；RPO/RTO 与验证状态同组。 |
| GLB-01～17 | 建立统一 Token/组件适配层；系统字体；状态不只靠颜色；移除黑色选中/原始 JSON 墙；稳定 Skeleton/局部错误；Bootstrap 消除 14～16 秒重接口阻塞。 |

## 实际视觉复核

本地连接实现生成 6 张 After 截图：

- Desktop：Overview、Services Detail、Incidents Detail；
- Mobile 390×844：Overview、Services、Incidents；
- 浅色中文/英文抽样；深色由 16 路由导航回归和 axe 覆盖。

人工复核确认：

- 导航文字、宽度、选中 Accent 与层级稳定；
- Overview 第一屏可以直接读出健康、Agent、告警、备份和 Gate；
- Services 不再出现卡片墙或默认 `<pre>`；
- systemd `0 loaded units listed` 显示“正常”；
- Incidents 选中行在 Drawer 遮罩外仍保持可读，不使用纯黑；
- 390px 的三条关键路由无文档横向溢出；
- 中文风险、Timeline 和检查结果不会直接显示 fixture 中的英文句子。

## 无障碍与安全

- axe 扫描 Overview、Services、Incidents：0 个 serious/critical violation。
- 导航浅/深主题实际计算对比度 ≥4.5:1；原型选中行为 light 14.37:1、
  dark 10.69:1。
- Detail Drawer 和手机导航限制焦点，ESC/遮罩关闭，关闭后归还焦点。
- 支持 `prefers-reduced-motion`。
- Evidence 使用 Vue 文本插值，不执行 HTML；Playwright 用恶意 `<img
  onerror>` fixture 验证没有 DOM 注入。
- Controller 在输出 Evidence 前处理 plain text、JSON 和 NDJSON Secret
  redaction。

## 真实 Staging 门禁结论

- 固定提交 `8722fabd28b3c6127fdfb8e2c630ed8fa94e5cfa` 和
  `v0.4.0-phase4-ui-v3-rc3-8722fab` 已部署到 Staging。
- 19 张真实数据 After 截图覆盖主要页面、桌面/移动端和明/暗主题；无横向溢出、
  `[object Object]` 或 `undefined`。
- 三次冷启动的中位 FCP 416 ms、LCP 580 ms、数据就绪 1,638 ms；12 个请求，
  0 个长任务。
- Bootstrap p50/p95 为 86/136 ms；HAR、Trace、Coverage 和报告已脱敏并生成
  SHA-256。
- 登录、TOTP、退出、旧 Cookie、无效 Bearer、普通偏好 Cookie 和深链接回归通过；
  page/console error 为 0。
- Overview、Services、Incidents 的 axe serious/critical 为 0。
- 部署前 PostgreSQL dump、异地 Restic snapshot、`check --read-data` 和回滚材料
  完成；Controller/Web 最长观测不可用时间 12.413 秒。
- 2/2 Agent 保持新鲜；Telegram 真实 warning/resolved 投递及审计通过；Discord
  按批准继续延期。

Staging Deployment、Real Staging Cold Load、UI Product Quality 与 Phase 4 UI V3：
**GO**。Production：**NO-GO**。
