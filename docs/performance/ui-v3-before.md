# UI V3 Performance Baseline — Before

状态：真实 Staging 基线

采集日期：2026-07-25

代码参考：`origin/main@6dc7488d3f2615e32ebcedb80f77d72bd1262ba2`
真实 Staging 应用：`5a970fc7a28e4e84d7b5b3bb50b0a3b1b72ac4b8`

## 结论

旧版首屏十几秒不是 Skeleton、浏览器猜测或无法归因的“网络问题”。主要瓶颈是
已登录 Overview 的单个 `/api/v1/overview` 请求：三次冷缓存实测
`14.501s / 15.651s / 14.713s`。该请求返回首屏不需要的大量历史、拓扑、恢复、
安全和时间线数据，同时后端执行 N+1 查询和大范围历史扫描。

当前真实 Staging 性能结论：**NO-GO**。

## 测试方法

- 独立浏览器审计配置，不复用日常浏览器状态。
- 真实 Staging，真实已登录会话；凭据和 Session 未写入仓库、脚本、命令行或报告。
- Chrome DevTools Protocol，禁用缓存，冷启动路由。
- 已登录和未登录分别至少 3 次，报告中位数和最差值。
- 保留 HAR、Performance Trace、Coverage、请求瀑布和截图在本机私有输出目录。
- 不以脚本的固定等待时间作为加载指标。
- 当前基线没有 `Server-Timing`，数据库阶段只能结合源码和接口墙钟进一步分解。

## 已登录 `/overview`

| 指标 | Run 1 | Run 2 | Run 3 | 中位数 | 最差 |
|---|---:|---:|---:|---:|---:|
| App Shell 可见 | 2823ms | 2772ms | 2559ms | 2772ms | 2823ms |
| 首屏关键数据完成 | 17420ms | 18467ms | 17199ms | 17420ms | 18467ms |
| FCP | 1992ms | 1976ms | 1768ms | 1976ms | 1992ms |
| LCP | 17308ms | 18292ms | 17136ms | 17308ms | 18292ms |
| CLS | 0.0036 | 0.0036 | 0.0036 | 0.0036 | 0.0036 |
| 请求数 | 21 | 21 | 21 | 21 | 21 |
| 资源传输 | 约 139.2KB | 约 139.2KB | 约 139.3KB | 约 139.2KB | 约 139.3KB |
| `/auth/me` | 371ms | 285ms | 294ms | 294ms | 371ms |
| `/api/v1/overview` | 14501ms | 15651ms | 14713ms | 14713ms | 15651ms |
| `/api/v1/stability` | 422ms | 353ms | 379ms | 379ms | 422ms |
| >200ms 主线程长任务 | 1 | 1 | 1 | 1 | 1 |

资源 decoded 总量约 401.5KB。三次均没有 console error、page error 或失败请求。
CLS 合格，但视觉稳定不抵消关键数据 17–18 秒才出现的问题。

### Run 1 请求瀑布

| 阶段 | 起点 | 持续/结果 |
|---|---:|---:|
| Document | 19ms | 约 806ms 后响应 |
| 初始 JS/CSS | 849ms | 开始下载 |
| `/auth/me` | 1963ms | 371ms |
| Overview 路由 chunks | 2338ms | 约 293–308ms |
| `/api/v1/overview` | 2670ms | 14501ms |
| `/api/v1/stability` | 2670ms | 422ms |

认证没有重复请求，但 App Shell 被 `session.ready` 阻塞，必须等待 `/auth/me` 才
渲染路由内容。Overview 数据请求并行发起；真正的长尾来自 `/overview` 本身，
不是前端把多个 API 串行排队。

## 未登录 `/overview`

未登录请求被正确引导至登录页，三次 `/auth/me` 都只请求一次。

| 指标 | 范围 |
|---|---:|
| FCP | 2008–2036ms |
| LCP | 2608–2980ms |
| 请求数 | 9 |
| 资源传输 | 约 115.8KB |
| 长任务 | 0 |

未登录首屏同样没有达到 1.0s App Shell 和 1.5s FCP 目标，说明 HTML/静态资源
路径及 Shell 阻塞也需要优化，但它不是已登录 17 秒关键数据延迟的主因。

## 源码根因

### 1. Shell 被认证恢复阻塞

`web/src/App.vue` 在 `session.ready` 前阻止 `RouterView` 渲染；路由守卫也调用
session restore，虽然 Promise 去重使 `/auth/me` 只有一次，但用户在认证完成前
看不到稳定 App Shell。

### 2. Overview 首屏接口过重

`OverviewView.vue` 同时等待 `/api/v1/overview` 和 `/api/v1/stability` 后才完成
页面数据态。`/overview` 返回首屏不必要的图表、拓扑、Hosts、Recovery、
Security 和 Timeline 等完整模块。

### 3. 后端查询范围过大

`build_operations_overview` 当前会：

- 读取所有 Hosts、Agents 和 Tasks；
- 对每个 Host 单独查询最新 MetricSnapshot，形成 N+1；
- 读取最多 50,001 条 metrics 后在 Python 中降采样；
- 读取 100 个 incidents、1000 个 alerts、100 个 approvals；
- 读取 100 个 repairs、500 个 recovery points；
- 读取全部 checks、5000 个 check results、500 个 notification deliveries。

这不是轻量 Dashboard bootstrap，应拆分为首屏摘要接口和延迟加载的详细模块。

### 4. Services 也存在 N+1

`controller/guardian/api.py` 的 services 列表会按 Host 查询最新 snapshot。阶段 2
需要批量查询或窗口查询，避免列表长度线性放大数据库往返。

### 5. 静态资源和 CSS

基线 production build：

| 资源 | 原始 | gzip |
|---|---:|---:|
| 全局 CSS | 59.02KB | 11.57KB |
| 初始 index JS | 46.57KB | 17.49KB |
| i18n chunk | 93.02KB | 32.24KB |
| Lucide 创建器 chunk | 110.20KB | 42.62KB |
| Overview route | — | 6.31KB |
| Services route | — | 3.20KB |
| Incidents route | — | 2.50KB |

Overview 的真实 CSS coverage 约 31.1%，说明全局 stylesheet 包含大量当前路由
未使用规则。基线 build 还启用了 production sourcemap；阶段 2 必须确保公开
构建不发布 source map，或把 map 严格留在受控分析产物中。

初始压缩资源约 104KB，加入首个路由后仍低于预算。因此静态资源不是 17 秒
延迟主因，但图标、i18n、CSS 和预加载策略仍有优化空间。

## 其他真实路由观察

一次完整路由截图流程中，Overview 约 18.6 秒、Topology 约 28.5 秒、Security
约 17.4 秒才满足当前页面“就绪”条件；多数其他路由约 2.4–2.8 秒。该组数字
包含现有页面自身的等待定义，只用于发现异常路由，不替代上面的分阶段指标。

Services 在 390px 出现页面级横向溢出，文档宽度达到约 522px；页面还包含
最多 20 个嵌套可滚动的 `<pre>`。这既是移动端缺陷，也会增加布局和可读性负担。

## 阶段 2 验证假设

正式实现应验证以下可证伪假设：

1. 立即渲染稳定 App Shell，把认证恢复变成 Shell 内的明确状态，可把 Shell
   可见时间降至 1 秒目标附近。
2. 新增 `GET /api/v1/dashboard/bootstrap`，只返回用户最小信息、环境、版本、
   5 个摘要和前 5 条 Attention，可消除 14–16 秒 Overview 阻塞。
3. metrics、Topology、Audit、Evidence 和完整历史在视口进入、空闲或用户交互
   后加载，首屏不再支付其查询和序列化成本。
4. 聚合查询、必要索引、5–15 秒隔离短缓存、ETag 和 `Server-Timing` 可让
   bootstrap 达到 p50 ≤500ms、p95 ≤1000ms，并能区分 db/cache/serialization。
5. 路由拆分、按需图标和移除未使用 CSS 可把请求数从 21 降至 ≤20，同时保持
   初始 JS/CSS 在预算内。

任何优化都必须用真实 Staging After 数据验证。只显示 Skeleton、隐藏数据或
延迟发起请求不算改善。
