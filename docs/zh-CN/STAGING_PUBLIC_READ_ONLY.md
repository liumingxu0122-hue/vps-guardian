# 公开只读 Staging 面板

公开面板是面向非生产 Staging 部署的可选、严格受限视图。它不是生产功能，也不改变生产
**NO-GO** 结论。

## 部署隔离

- 受保护面板（包括 `panel.liuwave.com`）保持
  `GUARDIAN_ANONYMOUS_READ_ONLY=false`，现有登录、Session、CSRF 和 RBAC 行为不变。
- 独立的公开 Staging 部署必须显式设置：

  ```dotenv
  GUARDIAN_DEPLOYMENT_STAGE=staging
  GUARDIAN_PRODUCTION_DEPLOYED=false
  GUARDIAN_ANONYMOUS_READ_ONLY=true
  ```

`GUARDIAN_ENVIRONMENT=production` 表示 Compose 使用生产级运行时加固规则，并不表示该
Staging 部署已经成为生产环境。部署层级由 `GUARDIAN_DEPLOYMENT_STAGE` 标识。匿名模式
用于任何非 Staging 层级，或系统被标记为已经部署生产时，Controller 都会拒绝启动。

## 公开边界

匿名访问通过专用 Public API 实现，不会获得现有 viewer 角色：

- `/api/v1/public/session` 的 `GET`、`HEAD` 和预检 `OPTIONS`
- `/api/v1/public/overview` 的 `GET`、`HEAD` 和预检 `OPTIONS`
- `/api/v1/public/hosts` 的 `GET`、`HEAD` 和预检 `OPTIONS`

其他 API 继续执行原有认证和 RBAC。公开 Web 导航只包含总览与主机清单。主机原始快照、
服务、告警、事故、修复、审批、恢复、审计、设置、Agent 身份、注册和通知页面均不公开。

Public DTO 直接声明允许字段，只包含展示名称、可选地区、健康状态、最近在线时间和受限的
CPU、内存、磁盘百分比。它不包含地址、操作系统资产、分组、标签、原始 Agent Payload、
服务检查配置、事故证据、证书、任务队列、内部拓扑、恢复元数据、安全扫描、审计、Secret、
Token 或修复数据。

## 凭据行为

只有 Bearer Token 和 `guardian_session` 认证 Cookie 属于显式凭据。只要其中任意一项存在，
就必须验证成功；无效或过期凭据返回 `401`，不得降级为匿名访问。语言、主题和其他普通
Cookie 不参与认证。

公开响应使用 `Cache-Control: no-store`。运维人员仍需保留既有 Trusted Host 与 Allowed
Origin 限制，严禁在生产或受保护面板启用此模式。

## 验证状态

自动测试只使用本地测试应用和合成数据。真实受保护面板测试必须显式启用，默认跳过。本功能
不授权部署、DNS 修改、面板切换或生产发布。
