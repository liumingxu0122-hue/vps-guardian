# UI V3 Performance Implementation

状态：本地实现与自动化门禁完成，真实 Staging After 尚未部署/测量

基线：`origin/main@6dc7488d3f2615e32ebcedb80f77d72bd1262ba2`
日期：2026-07-26

## 已关闭的 17 秒根因

旧版已登录 Overview 的关键数据中位数为 `17.420s`，最差 `18.467s`。
其中 `/api/v1/overview` 中位数为 `14.713s`，最差 `15.651s`。实现不再把该
接口或 `/stability` 放入首屏瀑布，而使用：

1. `/auth/me` 单次恢复；
2. `GET /api/v1/dashboard/bootstrap`；
3. 首屏 5 个 Summary 与前 5 条 Attention；
4. 进入视口后单独请求 `/api/v1/dashboard/resources/current`；
5. Topology、Audit、Evidence 和完整历史继续由各自路由或交互加载。

Bootstrap 不返回完整 metrics、Topology、Audit、Evidence、日志或事故历史。
Services 的最新 Agent 观察由按 Host 聚合的单次查询替代逐 Host N+1。

## 后端性能与缓存

- Bootstrap 缓存 TTL：10 秒。
- Cache key：用户 ID、角色、环境、版本、Production 状态和 Gate 决策。
- 成功写请求后清空摘要缓存。
- 响应提供私有 `ETag`、`304`、`Vary: Authorization, Cookie`。
- `Server-Timing` 提供 `db`、`cache`、`serialization`、`total`。
- 非关键 Backup 查询故障返回 `sections.backup.status=degraded`，不把整个
  Dashboard 伪装成空数据。
- `0011_dashboard_query_indexes` 增加：
  - `metric_snapshots(host_id, collected_at)`；
  - `incidents(status, severity, updated_at)`；
  - `recovery_points(verified, verified_at)`。
- migration 的 upgrade → downgrade → upgrade 已在全新 SQLite 数据库通过。
- Bootstrap 自动测试限制在 10 条 SQL statement 以内。

## 本地 Production Build 预算

| 项目 | UI V3 | 预算 | 结果 |
|---|---:|---:|---|
| 初始 index JS gzip | 19.19 KB | — | PASS |
| 初始共享 API/Vue chunk gzip | 42.56 KB | — | PASS |
| 初始 i18n chunk gzip | 32.20 KB | — | PASS |
| 初始 JS gzip 合计 | 93.95 KB | ≤180 KB | PASS |
| CSS gzip | 18.29 KB | ≤35 KB | PASS |
| Overview route gzip | 4.88 KB | — | PASS |
| Services route gzip | 8.54 KB | — | PASS |
| Incidents route gzip | 6.23 KB | — | PASS |
| Production sourcemap | 0 | 0 | PASS |

初始静态资源总 gzip 约 `112.2 KB`，不包含按路由加载的页面 chunk。
Production HTML 只 preload 初始共享 chunk 和 i18n；Topology 与 Evidence
不会被首屏预取。

## Bundle Analyzer：最大 20 个源模块

下表是受控 sourcemap 分析构建中的源输入大小，用于排序，不等同于最终 gzip
贡献。分析 sourcemap 仅保存在本机审计目录，常规 production build 不生成。

| # | Module | Source bytes |
|---:|---|---:|
| 1 | `@vue/runtime-core` | 273,903 |
| 2 | `vue-i18n` | 89,730 |
| 3 | `@intlify/core-base` | 67,092 |
| 4 | `vue-router` | 62,618 |
| 5 | `@vue/runtime-dom` | 62,605 |
| 6 | `@intlify/message-compiler` | 57,229 |
| 7 | `@vue/reactivity` | 54,588 |
| 8 | `vue-router/devtools` | 44,766 |
| 9 | `ServicesView.vue` | 29,211 |
| 10 | `@vue/shared` | 23,016 |
| 11 | `IncidentsView.vue` | 21,283 |
| 12 | `locales/en-US.ts` | 18,036 |
| 13 | `locales/zh-CN.ts` | 17,121 |
| 14 | `OverviewView.vue` | 16,681 |
| 15 | `OperationsLayout.vue` | 13,003 |
| 16 | `@intlify/shared` | 12,693 |
| 17 | `HostsView.vue` | 12,449 |
| 18 | `SettingsView.vue` | 10,597 |
| 19 | `UsersView.vue` | 9,920 |
| 20 | `IdentitySetupView.vue` | 7,959 |

没有新增图表库、日期库、UI 框架或远程字体。Lucide 使用命名 import。

## 本地浏览器门禁（非 Staging 结论）

Production bundle 的匿名登录页、无网络节流 Lighthouse：

| 指标 | 结果 |
|---|---:|
| Performance | 100 |
| Accessibility | 95 |
| Best Practices | 96 |
| FCP | 145 ms |
| LCP | 245 ms |
| TBT | 0 ms |
| CLS | 0 |
| Interactive | 145 ms |
| 请求 | 10 |
| 传输 | 116,926 bytes |

该数据只证明本地 production bundle 和匿名恢复没有静态性能回退，不能替代
真实 Staging 的跨网 TLS、Controller、PostgreSQL 和已登录数据测量。

## 真实 Staging After

固定应用提交：`8722fabd28b3c6127fdfb8e2c630ed8fa94e5cfa`

固定 RC：`v0.4.0-phase4-ui-v3-rc3-8722fab`

采集时间：2026-07-27 UTC

在真实、已认证、跨网 TLS 的 Staging 上执行三次禁用浏览器缓存的冷启动：

| 指标 | Run 1 | Run 2 | Run 3 | 中位数 | Before 中位数 | 改善 |
|---|---:|---:|---:|---:|---:|---:|
| App Shell 可见 | 411 ms | 391 ms | 367 ms | 391 ms | 2,772 ms | 85.9% |
| 首屏数据就绪 | 1,781 ms | 1,638 ms | 1,573 ms | 1,638 ms | 17,420 ms | 90.6% |
| FCP | 432 ms | 416 ms | 388 ms | 416 ms | 1,976 ms | 78.9% |
| LCP | 604 ms | 580 ms | 552 ms | 580 ms | 17,308 ms | 96.6% |
| CLS | 0.000657 | 0.000581 | 0.000675 | 0.000657 | 0.0036 | 81.8% |
| 请求数 | 12 | 12 | 12 | 12 | 21 | 42.9% |
| 传输字节 | 131,985 | 131,984 | 131,983 | 131,984 | 约 139,200 | 5.2% |
| >50 ms 主线程长任务 | 0 | 0 | 0 | 0 | 1 | 100% |

真实 API 浏览器墙钟分位数：

| 接口 | p50 | p95 | 备注 |
|---|---:|---:|---|
| `/api/v1/auth/me` | 65 ms | 77 ms | 每次冷启动仅一次 |
| `/api/v1/dashboard/bootstrap` | 86 ms | 136 ms | 首次 miss，随后命中隔离短缓存 |
| `/api/v1/dashboard/resources/current` | 115 ms | 173 ms | 与 bootstrap 独立加载 |

`Server-Timing` 证实 bootstrap 首次数据库阶段约 58 ms；后两次为用户隔离缓存
命中，总服务端阶段分别约 0.07 ms 和 0.04 ms。Topology 改用明确字段白名单的
轻量只读端点后，就绪时间为 1,172 ms；Security 同样不再读取重型 Overview。
七条抽样路由全部在 2 秒内就绪，最慢为 Hosts 1,977 ms。

真实认证回归通过：登录、TOTP、退出、退出后 Session 401、无效 Bearer 401、
旧 Session Cookie 返回登录页、普通主题/语言 Cookie 不被当成显式凭据，以及
`/services?status=issues` 深链接保留。浏览器 page error 和 console error 均为 0。
Overview、Services、Incidents 的 axe serious/critical 均为 0；19 张桌面、深色和
390px 移动端截图无横向溢出。

受控证据保存在本地私有目录
`outputs/ui-v3-staging-after-2026-07-27T134259-711Z`。敏感凭据未持久化，HAR 和
Coverage 已脱敏：

| 文件 | SHA-256 |
|---|---|
| `report.json` | `860396A0B101403F22459D6559350248130CAAEED66BD0C9D198F5C4CD17F41F` |
| `sanitized.har.json` | `D0B4D574860CECA0DC2288BD5FADBF860F30A8E7CC03282AE60F05DA66C16B1C` |
| `chrome-trace.json` | `9404D932ACF657D3C79A2E3BD0DD19568C27033805098BDEEDF202D0744798D4` |
| `coverage-sanitized.json` | `4C4F6B984BE65BF66E9040280CEB337492389ED5D4A7E5EDEC63F5A48605C5AA` |

部署前 PostgreSQL dump、异地 Restic snapshot、`check` 与
`check --read-data` 全部通过。Controller/Web 切换期间最长观测不可用时间为
12.413 秒；schema `0011`、2 个 Owner、TOTP、2/2 新鲜 Agent、Telegram、Gateway、
数据库和 Komari 均保持预期。真实 Telegram warning/resolved 投递和审计通过。

因此 Real Staging Cold Load、UI Product Quality 和 Phase 4 UI V3 为 **GO**。
该结论只适用于 Staging；Production 仍为 **NO-GO**。
