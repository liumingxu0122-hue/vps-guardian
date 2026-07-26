export type Tone = 'healthy' | 'warning' | 'critical' | 'info' | 'neutral'

export interface SummaryFixture {
  label: string
  value: string
  detail: string
  updated: string
  tone: Tone
}

export interface ServiceFixture {
  id: string
  name: string
  target: string
  type: string
  interval: string
  failures: number
  result: string
  latency: string
  updated: string
  incident: string
  tone: Tone
}

export interface IncidentFixture {
  id: string
  severity: string
  title: string
  resource: string
  status: string
  owner: string
  source: string
  created: string
  duration: string
  updated: string
  next: string
  tone: Tone
  test?: boolean
}

export const overviewSummaryZh: SummaryFixture[] = [
  {
    label: '系统健康',
    value: '需要关注',
    detail: '1 个证书到期提醒，0 个服务故障',
    updated: '2 分钟前',
    tone: 'warning',
  },
  {
    label: 'Guardian Agent',
    value: '2 / 2 在线',
    detail: '心跳和证书状态正常',
    updated: '34 秒前',
    tone: 'healthy',
  },
  {
    label: '活跃告警',
    value: '1 个警告',
    detail: '没有严重告警',
    updated: '2 分钟前',
    tone: 'warning',
  },
  {
    label: '最近已验证备份',
    value: '可恢复',
    detail: 'Offsite · check 与隔离恢复通过',
    updated: '7 小时前',
    tone: 'healthy',
  },
  {
    label: 'Production Gate',
    value: '未部署',
    detail: '等待 CRL 测试与长期观察',
    updated: '今天 09:20',
    tone: 'info',
  },
]

export const overviewSummaryEn: SummaryFixture[] = [
  {
    label: 'System health',
    value: 'Needs attention',
    detail: '1 certificate warning, 0 service failures',
    updated: '2 min ago',
    tone: 'warning',
  },
  {
    label: 'Guardian agents',
    value: '2 / 2 online',
    detail: 'Heartbeats and certificates are healthy',
    updated: '34 sec ago',
    tone: 'healthy',
  },
  {
    label: 'Active alerts',
    value: '1 warning',
    detail: 'No critical alerts',
    updated: '2 min ago',
    tone: 'warning',
  },
  {
    label: 'Latest verified backup',
    value: 'Recoverable',
    detail: 'Offsite · check and isolated restore passed',
    updated: '7 hr ago',
    tone: 'healthy',
  },
  {
    label: 'Production gate',
    value: 'Not deployed',
    detail: 'Waiting for CRL test and observation',
    updated: 'Today 09:20',
    tone: 'info',
  },
]

export const services: ServiceFixture[] = [
  {
    id: 'controller-docker',
    name: 'Controller · Docker',
    target: 'Controller-1',
    type: 'Docker',
    interval: '60 秒',
    failures: 0,
    result: '8 个容器运行正常',
    latency: '182 ms',
    updated: '34 秒前',
    incident: '—',
    tone: 'healthy',
  },
  {
    id: 'controller-systemd',
    name: 'Controller · systemd',
    target: 'Controller-1',
    type: 'systemd',
    interval: '60 秒',
    failures: 0,
    result: '未发现失败的 unit',
    latency: '74 ms',
    updated: '41 秒前',
    incident: '—',
    tone: 'healthy',
  },
  {
    id: 'edge-tls',
    name: 'Edge · TLS 证书',
    target: 'Edge-2',
    type: 'TLS',
    interval: '5 分钟',
    failures: 1,
    result: '证书将在 18 天后到期',
    latency: '212 ms',
    updated: '2 分钟前',
    incident: 'INC-024',
    tone: 'warning',
  },
  {
    id: 'gateway-http',
    name: 'Gateway · HTTP',
    target: 'Edge-2',
    type: 'HTTP',
    interval: '30 秒',
    failures: 0,
    result: '200 · 响应正常',
    latency: '96 ms',
    updated: '18 秒前',
    incident: '—',
    tone: 'healthy',
  },
  {
    id: 'postgres-port',
    name: 'Database · TCP',
    target: 'Controller-1',
    type: 'TCP',
    interval: '30 秒',
    failures: 0,
    result: '端口仅限回环访问',
    latency: '12 ms',
    updated: '21 秒前',
    incident: '—',
    tone: 'healthy',
  },
  {
    id: 'worker-journal',
    name: 'Worker · Journal',
    target: 'Worker-1',
    type: 'Journal',
    interval: '2 分钟',
    failures: 0,
    result: '没有新的 Error',
    latency: '134 ms',
    updated: '1 分钟前',
    incident: '—',
    tone: 'healthy',
  },
  {
    id: 'legacy-compose',
    name: 'Legacy · Compose',
    target: 'Archive-1',
    type: 'Compose',
    interval: '5 分钟',
    failures: 0,
    result: '等待首次采集',
    latency: '—',
    updated: '尚无数据',
    incident: '—',
    tone: 'neutral',
  },
]

export const incidents: IncidentFixture[] = [
  {
    id: 'INC-024',
    severity: 'S3',
    title: '边缘节点 TLS 证书即将到期',
    resource: 'Edge-2 · TLS',
    status: '调查中',
    owner: 'Liu',
    source: '证书检查',
    created: '7 月 25 日 09:14',
    duration: '4 小时',
    updated: '12 分钟前',
    next: '确认续期窗口',
    tone: 'warning',
  },
  {
    id: 'INC-023',
    severity: 'S4',
    title: '异地备份验证延迟',
    resource: 'Offsite backup',
    status: '观察中',
    owner: 'Liu',
    source: '备份门禁',
    created: '7 月 24 日 18:42',
    duration: '18 小时',
    updated: '1 小时前',
    next: '复核下次快照',
    tone: 'info',
  },
  {
    id: 'INC-021',
    severity: 'S5',
    title: '审批审计演练记录',
    resource: 'Staging · Approval',
    status: '已隔离',
    owner: '未分配',
    source: '审批审计',
    created: '7 月 20 日 13:32',
    duration: '历史记录',
    updated: '5 天前',
    next: '从健康聚合排除',
    tone: 'neutral',
    test: true,
  },
]

export const attentionZh = [
  {
    level: '警告',
    type: '证书',
    title: 'Edge-2 的 TLS 证书将在 18 天后到期',
    impact: '公开入口',
    time: '12 分钟前',
    owner: 'Liu',
    action: '确认续期窗口',
    tone: 'warning' as Tone,
  },
  {
    level: 'Info',
    type: 'Production Gate',
    title: 'CRL 验证尚未完成',
    impact: '阻止生产发布',
    time: '今天 09:20',
    owner: '未分配',
    action: '查看门禁',
    tone: 'info' as Tone,
  },
]

export const attentionEn = [
  {
    level: 'Warning',
    type: 'Certificate',
    title: 'Edge-2 TLS certificate expires in 18 days',
    impact: 'Public entry',
    time: '12 min ago',
    owner: 'Liu',
    action: 'Confirm renewal window',
    tone: 'warning' as Tone,
  },
  {
    level: 'Info',
    type: 'Production gate',
    title: 'CRL validation is not complete',
    impact: 'Blocks production release',
    time: 'Today 09:20',
    owner: 'Unassigned',
    action: 'Review gate',
    tone: 'info' as Tone,
  },
]
