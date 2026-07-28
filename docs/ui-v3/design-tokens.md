# UI V3 Design Tokens

状态：阶段 1 原型规范

适用范围：VPS Guardian Web UI
设计方向：专业、克制、高信息密度、可信的运维控制台

## 原则

- 先建立信息层级，再使用容器和颜色。
- 表格用于比较，紧凑列表用于处置队列，卡片仅用于真正独立的摘要。
- 状态必须同时使用图标、文字和颜色，不能只靠颜色。
- 选中态使用轻量 Accent 背景和内侧强调线，禁止大面积纯黑。
- 原始证据是按需展开的次级信息，不能代替产品化摘要。
- 使用系统字体，不引入阻塞首屏的远程字体。
- 动效只用于状态变化和空间关系，必须可中断并尊重 reduced motion。

## CSS Token 契约

Token 使用语义命名，页面不得直接写状态色。原型和正式实现共享同一组变量。

### 颜色：浅色

| Token | 值 | 用途 |
|---|---|---|
| `--color-canvas` | `#f4f6f8` | 应用画布 |
| `--color-surface` | `#ffffff` | 页面、Drawer、Popover |
| `--color-subtle` | `#eef2f3` | 次级分组、表头 |
| `--color-hover` | `#e9eeef` | 可交互悬停 |
| `--color-selected` | `#e6f2ee` | 轻量选中背景 |
| `--color-border` | `#cbd5d7` | 控件和重要边界 |
| `--color-border-subtle` | `#e2e8ea` | 行分隔 |
| `--color-text-primary` | `#17211f` | 主文字 |
| `--color-text-secondary` | `#465552` | 次级文字 |
| `--color-text-muted` | `#667572` | 辅助文字 |
| `--color-text-inverse` | `#f8fbfa` | 深色实心控件文字 |
| `--color-accent` | `#147d64` | 主要交互 |
| `--color-accent-strong` | `#0f684f` | Hover/pressed |
| `--color-focus` | `#207bc1` | 键盘焦点 |
| `--color-healthy` | `#247a52` | 正常 |
| `--color-warning` | `#a45f0a` | 警告 |
| `--color-critical` | `#b33a3a` | 严重 |
| `--color-info` | `#286ea8` | 信息 |
| `--color-neutral` | `#5f6d6b` | 中性、未知 |

### 颜色：深色

| Token | 值 | 用途 |
|---|---|---|
| `--color-canvas` | `#111715` | 应用画布 |
| `--color-surface` | `#18201e` | 页面、Drawer、Popover |
| `--color-subtle` | `#202a27` | 次级分组、表头 |
| `--color-hover` | `#27322f` | 可交互悬停 |
| `--color-selected` | `#173e34` | 轻量选中背景 |
| `--color-border` | `#42514d` | 控件和重要边界 |
| `--color-border-subtle` | `#2c3935` | 行分隔 |
| `--color-text-primary` | `#eef5f2` | 主文字 |
| `--color-text-secondary` | `#c0cbc7` | 次级文字 |
| `--color-text-muted` | `#93a39e` | 辅助文字 |
| `--color-text-inverse` | `#10201b` | 浅色实心控件文字 |
| `--color-accent` | `#62c3a4` | 主要交互 |
| `--color-accent-strong` | `#83d2b8` | Hover/pressed |
| `--color-focus` | `#6eb8ee` | 键盘焦点 |
| `--color-healthy` | `#67c792` | 正常 |
| `--color-warning` | `#e5a64f` | 警告 |
| `--color-critical` | `#ef8181` | 严重 |
| `--color-info` | `#7eb6e3` | 信息 |
| `--color-neutral` | `#9aa9a5` | 中性、未知 |

状态背景从相应前景色派生为低饱和、低面积色块；状态标签必须包含可读文字和
图标。正文对比度目标至少 4.5:1，大号文字至少 3:1，非文本控件边界至少 3:1。

## 字体

```css
--font-sans: ui-sans-serif, system-ui, "Segoe UI", "PingFang SC",
  "Microsoft YaHei", sans-serif;
--font-mono: ui-monospace, "Cascadia Code", "SFMono-Regular", Consolas,
  "Liberation Mono", monospace;
```

| Token | 字号 / 行高 | 字重 | 用途 |
|---|---|---:|---|
| `--text-page-title` | `24px / 32px` | 650 | 页面标题 |
| `--text-section-title` | `18px / 26px` | 650 | 区块标题 |
| `--text-card-title` | `15px / 22px` | 650 | 摘要标题 |
| `--text-body` | `14px / 21px` | 400 | 正文 |
| `--text-small` | `13px / 19px` | 400 | 辅助文字 |
| `--text-value` | `22px / 28px` | 650 | 关键值 |
| `--text-code` | `13px / 20px` | 400 | 技术字段与证据 |

技术 ID、SHA、UUID 和 Snapshot ID 只作为次级或详情字段，不作为页面主标题。
数字列使用 tabular nums。

## 间距与尺寸

使用 4px 基础单位：

```css
--space-1: 4px;
--space-2: 8px;
--space-3: 12px;
--space-4: 16px;
--space-5: 20px;
--space-6: 24px;
--space-8: 32px;
--space-10: 40px;
```

| 语义 | 尺寸 |
|---|---:|
| 桌面页面边距 | `24px` |
| 平板页面边距 | `20px` |
| 手机页面边距 | `16px` |
| 区块间距 | `24px` |
| Surface 内距 | `16–20px` |
| 表格行高 | `48px` |
| 紧凑列表行高 | `44px` |
| 表单控件高度 | `38px` |
| 展开导航宽度 | `220px` |
| 折叠导航宽度 | `64px` |
| 桌面详情 Drawer | `480–520px` |

## 圆角、边框与阴影

```css
--radius-sm: 6px;
--radius-md: 10px;
--radius-lg: 14px;
--border-width: 1px;
--shadow-overlay: 0 18px 48px rgb(10 24 20 / 18%);
```

- 表格、列表和页面区块主要使用分隔线，不层层套 Card。
- Badge 使用 `--radius-sm`，不使用全页面泛滥的胶囊形状。
- 阴影只用于 Drawer、Popover、Dialog、Tooltip 等浮层。

## 动效

```css
--motion-fast: 120ms;
--motion-standard: 160ms;
--motion-slow: 200ms;
--ease-standard: cubic-bezier(.2, .8, .2, 1);
```

- Drawer 使用 160–200ms 的位移与透明度过渡，支持中途反向关闭。
- Hover 和状态变化使用 120–160ms。
- Skeleton 不能造成最终内容位移。
- `prefers-reduced-motion: reduce` 下取消非必要过渡和循环动画。
- 不为视觉装饰增加首屏主线程工作。

## 组件语义

### 状态

正式状态枚举：

- `HEALTHY`
- `WARNING`
- `CRITICAL`
- `INFO`
- `NEUTRAL`
- `NO_DATA`
- `DISABLED`
- `EXECUTION_FAILED`
- `PARSE_FAILED`
- `UNSUPPORTED`

Services 的检查语义映射为：

- `CHECK_HEALTHY`
- `CHECK_WARNING`
- `CHECK_CRITICAL`
- `CHECK_EXECUTION_FAILED`
- `CHECK_NO_DATA`
- `CHECK_UNSUPPORTED`
- `CHECK_PARSE_FAILED`
- `CHECK_DISABLED`

“成功执行并返回空异常集合”必须映射为 `CHECK_HEALTHY`。

### 选中

- 背景：`--color-selected`
- 文字：`--color-text-primary`
- 内侧强调：2px `--color-accent`
- 键盘焦点：2px `--color-focus`，与选中态同时可辨
- 禁止把黑色当作选中语义

### Surface 使用

- `SummaryMetric`：回答单一运营问题，最多 5 个紧凑摘要。
- `DataTable`：需要跨行比较的数据。
- `CompactList`：Attention、活动流和处置队列。
- `DetailDrawer`：上下文内查看详情和采取操作。
- `EvidenceViewer`：默认关闭的原始证据；独立滚动，不能让页面横向溢出。
- `StatusBadge`：只用于真正的状态，不用于版本、所有元数据或普通标签。

## 响应式

### 390px

- 主导航改为 Drawer，打开后锁定背景滚动。
- Summary 单列或两列；表格转换为带字段标签的紧凑列表。
- 筛选器进入 Sheet，详情 Drawer 全屏。
- 证据查看器可独立横向滚动，页面本身不得横向滚动。
- 保留最小 44px 触控目标。

### 768px

- 导航默认折叠为 64px，可显式展开。
- 表格只保留核心列，次要字段进入详情。
- 详情使用 Drawer，不创建三列过窄卡片。

### 桌面

- 220px 导航，内容最大宽度由信息类型决定，不强制所有页面同一窄宽。
- App Shell 只产生一个主内容滚动区域。
- 低高度导航允许内部滚动，但底部账户区固定且不与主内容形成模糊双滚动。

## 无障碍与交互

- 当前路由使用 `aria-current="page"`。
- Drawer/Dialog 打开后移动焦点、限制焦点范围，ESC 和遮罩可关闭，关闭后归还焦点。
- Tooltip 不能承载完成任务所必需的信息。
- 所有图标按钮有可见名称或 `aria-label`；危险操作有明确文字和二次确认。
- 表格使用正确表头、scope 和行操作名称。
- 错误、空数据和加载状态互相独立；503 不显示成“暂无数据”。
- Email、ID 等截断内容提供可访问的完整值提示。

## 性能预算

| 指标 | 预算 |
|---|---:|
| 初始 JS gzip | `≤ 180 KB` |
| 初始 CSS gzip | `≤ 35 KB` |
| 首屏静态传输 | `≤ 400 KB` |
| 首屏请求数 | `≤ 20` |
| `/auth/me` | `1` 次 |
| Dashboard bootstrap | `1` 次 |
| App Shell 可见 | `≤ 1.0s` |
| FCP | `≤ 1.5s` |
| LCP | `≤ 2.5s` |
| 首屏可操作/关键数据 | `≤ 3.0s` |
| Bootstrap p50 / p95 | `≤ 500ms / 1000ms` |
| CLS | `≤ 0.1` |

首屏不得加载完整 Topology、Audit、EvidenceViewer、30 天指标或原始日志。图表、
Topology 和 EvidenceViewer 必须按路由或交互动态加载。
