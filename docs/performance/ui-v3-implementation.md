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

## Staging After 待填

只有部署固定 RC 后才能填写：

- App Shell、FCP、LCP、CLS、关键数据完成；
- Bootstrap p50/p95 与 `Server-Timing` 分解；
- 冷缓存至少 3 次的中位数与最差值；
- HAR、Trace、Coverage、请求瀑布与长任务；
- 二次路由和缓存命中；
- 与 Before 的改善百分比。

在这些真实证据完成前，Real Staging Cold Load 和 Phase 4 UI V3 保持 **NO-GO**。
