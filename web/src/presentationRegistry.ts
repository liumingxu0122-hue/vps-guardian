import type { HostPresentation } from './types'

export type ProductLocale = 'en-US' | 'zh-CN'
export type PresentationTone = 'healthy' | 'warning' | 'critical' | 'info' | 'neutral'

const labels = {
  health: {
    healthy: ['Healthy', '健康'],
    degraded: ['Degraded', '性能下降'],
    offline: ['Offline', '离线'],
    unknown: ['Unknown', '未知'],
    normal: ['Normal', '正常'],
    no_data: ['Awaiting data', '等待数据'],
    stale: ['Data stale', '数据不新鲜'],
    agent_error: ['Agent error', 'Agent 异常'],
    disabled: ['Disabled', '已停用'],
  },
  management: {
    guardian_and_komari: ['Guardian + Komari', 'Guardian + Komari'],
    guardian: ['Guardian managed', 'Guardian 管理'],
    komari_only: ['Komari observed', 'Komari 观测'],
    pending_enrollment: ['Enrollment pending', '等待接入'],
  },
  agent: {
    online: ['Reporting', '正常上报'],
    stale: ['Heartbeat stale', '心跳不新鲜'],
    never_seen: ['Never reported', '从未上报'],
    revoked: ['Identity revoked', '身份已撤销'],
    not_installed: ['Not installed', '未安装'],
  },
  result: {
    success: ['Succeeded', '成功'],
    denied: ['Denied', '已拒绝'],
    failed: ['Failed', '失败'],
    error: ['Error', '错误'],
    detected: ['Detected', '已检测'],
    skipped: ['Skipped', '已跳过'],
    expired: ['Expired', '已过期'],
    partial: ['Partially completed', '部分完成'],
  },
} as const

function localized(pair: readonly [string, string], locale: string): string {
  return locale === 'zh-CN' ? pair[1] : pair[0]
}

export function healthLabel(value: string, locale: string): string {
  const pair = labels.health[value as keyof typeof labels.health]
  return pair ? localized(pair, locale) : localized(['Needs review', '需要检查'], locale)
}

export function managementLabel(value: HostPresentation['management'], locale: string): string {
  return localized(labels.management[value], locale)
}

export function agentLabel(value: HostPresentation['agent_state'], locale: string): string {
  return localized(labels.agent[value], locale)
}

export function dataReasonLabel(value: HostPresentation['data_reason'], locale: string): string {
  const registry: Record<HostPresentation['data_reason'], readonly [string, string]> = {
    available: ['Metrics are reporting normally', '指标正在正常上报'],
    no_guardian_agent: ['Observed without a Guardian Agent', '仅观测，尚未安装 Guardian Agent'],
    never_connected: ['Guardian Agent has never sent a heartbeat', 'Guardian Agent 尚未发送过心跳'],
    pending_enrollment: ['Waiting for Agent enrollment', '等待 Agent 完成注册'],
    disabled: ['Health alerts are disabled for this host', '该主机已停用健康告警'],
    stale: ['The latest heartbeat is outside the freshness window', '最近心跳已超过新鲜度窗口'],
    agent_error: ['The Guardian Agent reported an error', 'Guardian Agent 报告了错误'],
  }
  return localized(registry[value], locale)
}

export function regionLabel(value: string | null, locale: string): string {
  if (!value) return localized(['Not set', '未设置'], locale)
  const registry: Record<string, readonly [string, string]> = {
    ch: ['Switzerland', '瑞士'],
    hk: ['Hong Kong', '香港'],
    'hong kong': ['Hong Kong', '香港'],
    jp: ['Japan', '日本'],
    japan: ['Japan', '日本'],
    sg: ['Singapore', '新加坡'],
    singapore: ['Singapore', '新加坡'],
    tw: ['Taiwan', '台湾'],
    taiwan: ['Taiwan', '台湾'],
    us: ['United States', '美国'],
    'united states': ['United States', '美国'],
  }
  return localized(registry[value.toLocaleLowerCase()] ?? [value, value], locale)
}

export function resultLabel(value: string, locale: string): string {
  const pair = labels.result[value as keyof typeof labels.result]
  return pair ? localized(pair, locale) : localized(['Recorded', '已记录'], locale)
}

export function healthTone(value: string): PresentationTone {
  if (value === 'healthy' || value === 'normal' || value === 'success' || value === 'online') return 'healthy'
  if (value === 'offline' || value === 'failed' || value === 'error' || value === 'revoked') return 'critical'
  if (value === 'degraded' || value === 'stale' || value === 'agent_error' || value === 'denied') return 'warning'
  return 'neutral'
}

export function auditActionLabel(actionCode: string, fallback: string, locale: string): string {
  const zh: Record<string, string> = {
    'auth.login': '用户登录',
    'auth.logout': '用户退出',
    'auth.login_failed': '登录被拒绝',
    'session.revoke': '撤销会话',
    'host.create': '添加主机',
    'host.update': '更新主机',
    'host.delete': '移除主机',
    'host.stale': '主机数据不新鲜',
    'host.offline': '主机离线',
    'host.register': '注册主机',
    'user.create': '创建用户',
    'user.update': '更新用户',
    'user.delete': '移除用户',
    'approval.approved': '批准操作',
    'approval.created': '创建审批',
    'approval.rejected': '拒绝操作',
    'notification.phase4_acceptance': '发送 Phase 4 验收通知',
  }
  if (locale === 'zh-CN') return zh[actionCode] ?? '未知审计动作'
  return fallback === 'Unknown audit action' ? 'Unknown audit action' : fallback
}

export function resourceTypeLabel(value: string, locale: string): string {
  const registry: Record<string, readonly [string, string]> = {
    host: ['Host', '主机'],
    user: ['User', '用户'],
    incident: ['Incident', '事件'],
    approval: ['Approval', '审批'],
    service_check: ['Service check', '服务检查'],
    session: ['Session', '会话'],
    agent: ['Agent', 'Agent'],
    alert: ['Alert', '告警'],
  }
  return localized(registry[value] ?? ['Resource', '资源'], locale)
}

export function auditSourceLabel(value: string, locale: string): string {
  const registry: Record<string, readonly [string, string]> = {
    internal_service: ['Controller internal service', 'Controller 内部服务'],
    private_network: ['Private network client', '私有网络客户端'],
    external_client: ['External client', '外部客户端'],
    unknown: ['Unknown source', '未知来源'],
  }
  return localized(registry[value] ?? registry.unknown, locale)
}

export function auditActorLabel(value: string, fallback: string, locale: string): string {
  if (value === 'system') return localized(['Controller service', 'Controller 服务'], locale)
  if (value === 'agent') return localized(['Guardian Agent', 'Guardian Agent'], locale)
  if (value === 'unknown') return localized(['Unknown actor', '未知操作者'], locale)
  return fallback
}

const productLabels: Record<string, Record<string, readonly [string, string]>> = {
  severity: {
    info: ['Information', '提示'],
    warning: ['Warning', '警告'],
    critical: ['Critical', '严重'],
  },
  notification: {
    telegram: ['Telegram', 'Telegram'],
    smtp: ['Email', '邮件'],
    discord: ['Discord', 'Discord'],
    webhook: ['Webhook', 'Webhook'],
  },
  check: {
    http: ['HTTP', 'HTTP'],
    https: ['HTTPS', 'HTTPS'],
    tcp: ['TCP', 'TCP'],
    icmp: ['Ping', 'Ping'],
    docker: ['Container', '容器'],
    systemd: ['System service', '系统服务'],
  },
  attention: {
    host_offline: ['Host offline', '主机离线'],
    host_stale: ['Host data stale', '主机数据不新鲜'],
    service_failed: ['Service check failed', '服务检查失败'],
    incident_open: ['Open incident', '未关闭事件'],
    approval_pending: ['Approval pending', '等待审批'],
  },
  risk: {
    low: ['Low risk', '低风险'],
    medium: ['Medium risk', '中风险'],
    high: ['High risk', '高风险'],
  },
}

export function productLabel(domain: keyof typeof productLabels, value: string, locale: string): string {
  const pair = productLabels[domain]?.[value]
  return pair ? localized(pair, locale) : localized(['Other', '其他'], locale)
}

export function configurationLabel(value: string, locale: string): string {
  const registry: Record<string, readonly [string, string]> = {
    uncovered_critical: ['Uncovered critical findings', '未覆盖的严重发现'],
    uncovered_high: ['Uncovered high findings', '未覆盖的高风险发现'],
    mtls: ['Mutual TLS', '双向 TLS'],
    crl: ['Certificate revocation', '证书撤销'],
    certificate_rotation: ['Certificate rotation', '证书轮换'],
    last_scan_at: ['Last security scan', '最近安全扫描'],
    login_rate_limit: ['Login rate limiting', '登录速率限制'],
    totp: ['Two-factor authentication', '双因素认证'],
    rbac: ['Role-based access', '基于角色的访问控制'],
    audit: ['Append-only audit', '仅追加审计'],
    allowed_origins: ['Allowed web origins', '允许的 Web 来源'],
    agent_offline_after_seconds: ['Agent offline threshold', 'Agent 离线阈值'],
    metric_retention_days: ['Metric retention', '指标保留时间'],
    service_result_retention_days: ['Service result retention', '服务结果保留时间'],
    external_notifications_enabled: ['External notifications', '外部通知'],
    database_reference: ['Database credential reference', '数据库凭据引用'],
    token_signing_material: ['Token signing material', 'Token 签名材料'],
    field_encryption_material: ['Field encryption material', '字段加密材料'],
    agent_enrollment_material: ['Agent enrollment material', 'Agent 注册材料'],
    trusted_proxy_header_secret: ['Trusted proxy verification', '可信代理验证'],
    request_signatures: ['Request signatures', '请求签名'],
    level2_default_enabled: ['Level 2 automation default', 'Level 2 自动化默认值'],
    level3_requires_approval: ['Level 3 approval gate', 'Level 3 审批门禁'],
    arbitrary_shell: ['Arbitrary shell execution', '任意 Shell 执行'],
    multi_vps_enrollment: ['Multi-node enrollment', '多节点注册'],
    persistent_alerts: ['Persistent alerts', '持久化告警'],
    notification_retry: ['Notification retry', '通知重试'],
  }
  return localized(registry[value] ?? ['Configuration item', '配置项'], locale)
}
