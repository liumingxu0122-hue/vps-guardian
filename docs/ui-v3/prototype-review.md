# UI V3 阶段 1 原型评审

状态：**通过内部评审，可进入阶段 2 实现**

评审对象：App Shell、Overview、Services、Incidents

数据来源：项目内结构化、非敏感 fixtures
部署状态：仅本地；未接真实 API；未部署 Staging 或 Production

## 原型隔离

原型入口是 `web/prototype.html`，只由 Vite 开发服务器直接提供。常规 production
build 仍只以 `web/index.html` 为入口；构建产物没有包含 `prototype.html` 或
fixture chunk。fixture 不进入真实应用路由和 API 数据路径。

## 截图矩阵

已生成 30 张本地截图：

- Overview、Services、Incidents
- `1920 × 1080`、`1366 × 768`、`390 × 844`
- 浅色、深色
- Services 详情、原始证据展开
- Incidents 详情与 Timeline

截图保存在本机私有审计输出目录，不提交 Git。自动审计覆盖 18 个基础组合；
没有 page error、console error、页面级横向溢出、零宽度选中项或缺失
`aria-current`。

## 视觉评审结果

| 门槛 | 结果 | 证据 |
|---|---|---|
| 当前导航文字可见 | PASS | 选中项有文字、图标、内侧 3px Accent 和 `aria-current="page"`。 |
| 当前导航对比度 | PASS | `#f3fbf8` / `#23463c` 为 `9.92:1`。 |
| 未选中导航可读 | PASS | `#c8d2cf` / `#18201e` 为 `10.74:1`。 |
| 无桌面双滚动 | PASS | App Shell 只有主内容滚动；导航仅在自身内容确实超过低高度时滚动。 |
| Services 不是卡片墙 | PASS | 默认是一张高密度比较表；7 个检查可在 1366px 一屏比较。 |
| 技术 ID 降级 | PASS | 产品化名称为主，技术 ID 作为小号次级字段。 |
| 异常可快速识别 | PASS | 摘要计数、只看异常、统一状态语义、最近结果和延迟在首层。 |
| 原始 JSON 默认隐藏 | PASS | 证据位于详情 Drawer 的折叠区；默认关闭。 |
| systemd 空异常集合 | PASS | 明确显示“正常 · 未发现失败的 systemd unit”。 |
| Incidents 不用黑色选中行 | PASS | 使用浅 Accent 背景和左侧强调线。 |
| 浅色选中行对比度 | PASS | `#17211f` / `#e6f2ee` 为 `14.37:1`。 |
| 深色选中行对比度 | PASS | `#eef5f2` / `#173e34` 为 `10.69:1`。 |
| 无无意义 0% 置信度 | PASS | 列表不展示置信度；没有可靠模型结果时不制造百分比。 |
| 事故详情完整 | PASS | Drawer 包含影响、Owner、时间、来源、下一步决策和 Timeline。 |
| 测试事故可区分 | PASS | 明确“测试记录”，并说明已从全局健康聚合隔离。 |
| Overview 回答五个问题 | PASS | 5 个紧凑摘要分别覆盖健康、Agent、告警、备份和 Production Gate。 |
| 图表不阻塞首层 | PASS | 当前值先显示，历史图表为明确的按需加载占位。 |
| 中文没有随机英文句子 | PASS | 保留允许的技术专有名词；解释文案已中文化。 |
| 390px 无页面横向溢出 | PASS | 18 个基础组合的 `scrollWidth <= clientWidth`。 |
| 手机信息仍可读 | PASS | Summary 单列，表格转带字段标签的紧凑列表，详情全屏。 |
| 深色主题可读 | PASS | Surface、状态和层级均使用独立深色 Token。 |
| 不是只换色和圆角 | PASS | Shell、导航、页面 IA、数据表达、详情模式和证据层级均已重构。 |

## 评审中发现并关闭的问题

1. 第一轮手机 Services 行操作按钮因 block table cell 保留 100% 宽度而定位到
   左边。已将移动端操作 cell 改为自适应宽度，复核后位于行右上角。
2. 第一轮中文状态仍包含零散 Warning/Critical。已把产品解释文案收敛为
   “警告/严重”，仅在英文 locale 使用英文状态。
3. 1366px 的多列表格最初需要轻微内部横向滚动。已按优先级隐藏非核心列，
   完整字段仍在详情中；手机端则转换为字段标签列表。

## 对正式实现的约束

原型通过不代表功能完成。阶段 2 仍必须：

- 把设计 Token 和组件迁移到真实 App Shell，而不是长期维护两套 CSS。
- 使用真实 API DTO，并保持 fixtures 与 production 路径隔离。
- 实现 Drawer focus trap、焦点归还、遮罩/ESC 关闭和手机背景滚动锁定测试。
- 为所有真实路由补选中导航文字、对比度、`aria-current` 和 390px 回归测试。
- 实现 Services 的状态解析单元测试和明确的删除/批量操作风险交互。
- 实现 Incidents 的筛选 URL、空状态、历史测试数据隔离和聚合语义。
- 完成 Dashboard bootstrap、查询优化和真实 Staging After 性能验证。
- 统一其他主页面后才能评估 UI V3 GO。

阶段 1 结论只授权进入代码实现和测试；Production 继续 **NO-GO**。
