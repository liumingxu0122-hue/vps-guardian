import { expect, test, type Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

import type {
  ApprovalDetail,
  ApprovalEvidence,
  ApprovalSummary,
  AuditPresentation,
  Host,
  HostPresentation,
  Incident,
  ServiceCheck,
  ServiceCheckResult,
  ServiceSummary,
  User,
} from '../src/types'
import type {
  DashboardBootstrap,
  DashboardSecurity,
  DashboardTopology,
} from '../src/dashboard'

const captureDirectory = process.env.UI_V3_CAPTURE_DIR

async function capture(page: Page, name: string): Promise<void> {
  if (!captureDirectory) return
  await page.screenshot({ path: `${captureDirectory}/${name}.png`, fullPage: true })
}

const user: User = {
  id: 'user-1',
  email: 'owner@example.test',
  role: 'owner',
  totp_enabled: true,
  is_active: true,
  scopes: [],
  last_login_at: '2026-07-25T08:00:00Z',
  password_changed_at: '2026-07-20T08:00:00Z',
  totp_enabled_at: '2026-07-20T08:00:00Z',
  disabled_at: null,
  must_change_password: false,
  identity_setup_required: false,
  created_by: null,
  disabled_by: null,
  created_at: '2026-07-01T00:00:00Z',
}

const bootstrap: DashboardBootstrap = {
  generated_at: '2026-07-25T08:00:00Z',
  user: { id: user.id, email: user.email, role: user.role },
  environment: {
    stage: 'staging',
    version: '0.4.0-phase4-ui-v3',
    production_deployed: false,
    production_status: 'not_deployed',
    gate_decision: 'production_no_go',
    deployed_at: null,
  },
  global_health: {
    status: 'warning',
    reason: '1 active warning condition',
    critical: 0,
    warning: 1,
    updated_at: '2026-07-25T08:00:00Z',
  },
  agents: { total: 2, online: 2, offline: 0, updated_at: '2026-07-25T08:00:00Z' },
  alerts: { active: 1, critical: 0, warning: 1, info: 0, updated_at: '2026-07-25T08:00:00Z' },
  backup: {
    status: 'healthy',
    scope: 'offsite',
    verified: true,
    verified_at: '2026-07-25T07:50:00Z',
    created_at: '2026-07-25T07:45:00Z',
    check_status: 'passed',
    restore_status: 'passed',
    rpo_seconds: 20,
    rto_seconds: 55,
  },
  production_gate: {
    status: 'blocked',
    decision: 'production_no_go',
    production_deployed: false,
    blockers: ['discord_deferred', 'crl_revalidation', '24h_7d_observation'],
  },
  attention: [{
    id: 'incident-1',
    kind: 'incident',
    severity: 'warning',
    severity_level: 3,
    title: 'Reverse proxy backend requires attention',
    fault_type: 'reverse_proxy_backend',
    impact: { hosts: ['edge-hk'], services: ['gateway'] },
    owner: user.email,
    status: 'investigating',
    occurred_at: '2026-07-25T07:30:00Z',
    updated_at: '2026-07-25T07:58:00Z',
    next_action: 'Confirm mitigation',
    href: '/incidents?selected=incident-1',
  }],
  sections: {
    health: { status: 'ok' },
    agents: { status: 'ok' },
    alerts: { status: 'ok' },
    backup: { status: 'ok' },
    attention: { status: 'ok' },
  },
}

const hosts: Host[] = [{
  id: 'host-1',
  name: 'edge-hk',
  address: '192.0.2.10',
  os_name: 'Ubuntu 24.04',
  location: 'Hong Kong',
  status: 'healthy',
  data_state: 'normal',
  enabled: true,
  group_name: 'edge',
  tags: ['staging'],
  labels: {},
  last_seen_at: '2026-07-25T07:59:50Z',
  enrolled_at: '2026-07-01T00:00:00Z',
  disabled_at: null,
}]

const hostPresentations: HostPresentation[] = [{
  id: 'host-1',
  name: 'edge-hk',
  primary_address: '192.0.2.10',
  os_name: 'Ubuntu 24.04',
  region: 'Hong Kong',
  group: 'edge',
  provider: 'Example Cloud',
  purpose: 'Public gateway',
  display_tags: ['staging'],
  health: 'healthy',
  data_state: 'normal',
  enabled: true,
  management: 'guardian_and_komari',
  agent_state: 'online',
  agent_version: '0.4.0',
  last_heartbeat_at: '2026-07-25T07:59:50Z',
  last_seen_at: '2026-07-25T07:59:50Z',
  enrolled_at: '2026-07-01T00:00:00Z',
  data_reason: 'available',
  resource_summary: { cpu_percent: 22, memory_percent: 50, disk_percent: 50 },
  technical_evidence_available: true,
}]

const auditPresentations: AuditPresentation[] = [{
  event_id: 17,
  display_action: 'Signed in',
  action_code: 'auth.login',
  category: 'auth',
  severity: 'neutral',
  result: 'success',
  actor_display: 'owner@example.test',
  actor_type: 'user',
  actor_id: 'user-1',
  resource_display: 'Session',
  resource_type: 'session',
  resource_id: 'session-17',
  source_display: 'Controller internal service',
  source_type: 'internal_service',
  client_ip: null,
  internal_ip: '172.19.0.4',
  created_at: '2026-07-25T07:59:00Z',
  summary: 'Signed in · Session',
  changes: {},
  correlation_id: 'request-17',
  request_id: 'request-17',
  evidence_available: true,
}]

const checks: ServiceCheck[] = [
  {
    id: 'check-1',
    name: 'phase4-controller-https',
    kind: 'https',
    enabled: true,
    host_id: 'host-1',
    runner_agent_id: null,
    configuration: { target: 'https://example.test/health' },
    group_name: 'control',
    interval_seconds: 60,
    timeout_seconds: 5,
    failure_threshold: 3,
    recovery_threshold: 2,
    severity: 'critical',
    last_checked_at: '2026-07-25T07:59:45Z',
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-25T07:59:45Z',
  },
  {
    id: 'check-2',
    name: 'phase4-systemd-failed',
    kind: 'systemd',
    enabled: true,
    host_id: 'host-1',
    runner_agent_id: null,
    configuration: { unit: '--failed' },
    group_name: 'system',
    interval_seconds: 60,
    timeout_seconds: 5,
    failure_threshold: 2,
    recovery_threshold: 2,
    severity: 'warning',
    last_checked_at: '2026-07-25T07:59:40Z',
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-25T07:59:40Z',
  },
]

const results: ServiceCheckResult[] = checks.map((check, index) => ({
  id: index + 1,
  check_id: check.id,
  status: 'ok',
  checked_at: check.last_checked_at!,
  latency_ms: 18 + index,
  status_code: check.kind === 'https' ? 200 : null,
  message: 'Check passed',
  details: {},
}))

const observations: ServiceSummary[] = [{
  host_id: 'host-1',
  host_name: 'edge-hk',
  kind: 'systemd_failed',
  status: 'healthy',
  reason: 'No failed systemd units',
  counts: { failed: 0 },
  parsed: true,
  summary: '0 loaded units listed. <img src=x onerror=globalThis.__evidenceInjected=true>',
  evidence_available: true,
  collected_at: '2026-07-25T07:59:50Z',
}]

const incidents: Incident[] = [
  {
    id: 'incident-1',
    title: 'Reverse proxy backend requires attention',
    fault_type: 'reverse_proxy_backend',
    severity: 3,
    status: 'investigating',
    assigned_to: user.id,
    acknowledged_at: '2026-07-25T07:35:00Z',
    confidence: 0,
    affected_hosts: ['edge-hk'],
    affected_services: ['gateway'],
    evidence: [{ source: 'service-check' }],
    excluded_causes: [],
    recommendations: ['Confirm mitigation'],
    auto_repair_allowed: false,
    risk: 'Gateway requests may fail',
    verification_plan: ['Verify loopback health'],
    first_seen_at: '2026-07-25T07:30:00Z',
    updated_at: '2026-07-25T07:58:00Z',
    resolved_at: null,
    resolution_summary: null,
    postmortem: null,
    timeline: [{ title: 'Investigation started', at: '2026-07-25T07:35:00Z' }],
  },
  {
    id: 'incident-test',
    title: 'Approval test record',
    fault_type: 'approval_audit',
    severity: 5,
    status: 'open',
    assigned_to: null,
    acknowledged_at: null,
    confidence: 0,
    affected_hosts: [],
    affected_services: [],
    evidence: [],
    excluded_causes: [],
    recommendations: [],
    auto_repair_allowed: false,
    risk: 'none',
    verification_plan: [],
    first_seen_at: '2026-07-24T07:30:00Z',
    updated_at: '2026-07-24T07:30:00Z',
    resolved_at: null,
    resolution_summary: null,
    postmortem: null,
    timeline: [],
  },
]

const approvalSummaries: ApprovalSummary[] = [
  {
    id: 'approval-pending-1',
    incident_id: 'incident-1',
    action_name: 'service_restart',
    status: 'pending',
    risk_level: 2,
    target: { host: 'edge-hk', service: 'gateway', scope: 'staging' },
    requester: { label: 'operator', role: 'operator' },
    requested_at: '2026-07-25T07:40:00Z',
    expires_at: '2026-07-25T09:40:00Z',
    progress_label: 'awaiting_decision',
    execution_status: null,
  },
  {
    id: 'approval-executed-2',
    incident_id: 'incident-test',
    action_name: 'restricted_cleanup',
    status: 'executed',
    risk_level: 3,
    target: { host: 'worker-hk', service: 'filesystem', scope: 'staging' },
    requester: { label: 'owner', role: 'owner' },
    requested_at: '2026-07-24T07:40:00Z',
    expires_at: '2026-07-24T09:40:00Z',
    progress_label: 'completed',
    execution_status: 'completed',
  },
]

const approvalDetail: ApprovalDetail = {
  ...approvalSummaries[0],
  risk_reason: 'level_2_operational_change',
  approver: null,
  decided_at: null,
  executed_at: null,
  impact_facts: [
    { key: 'service', value: 'gateway', tone: 'neutral' },
    { key: 'downtime', value: 'under 30 seconds', tone: 'warning' },
  ],
  steps: [{ order: 1, action: 'service_restart', target: 'gateway.service', dry_run: true }],
  dry_run_available: true,
  dry_run_status: null,
  recovery_point_label: 'verified snapshot',
  rollback_available: true,
  rollback_steps: ['Restore the previous service unit', 'Verify loopback health'],
  timeline: [{
    at: '2026-07-25T07:40:00Z',
    event: 'requested',
    actor: 'operator',
    outcome: 'pending',
  }],
  raw_evidence_available: true,
}

const approvalEvidence: ApprovalEvidence = {
  approval_id: approvalDetail.id,
  parameters: { agent_id: 'agent-1', token: '[REDACTED]' },
  impact: { service: 'gateway' },
}

const resources = {
  generated_at: '2026-07-25T08:00:00Z',
  sampled_hosts: 2,
  current: {
    cpu_percent: 28.2,
    memory_percent: 51.4,
    disk_percent: 67.1,
    network_bytes_per_second: 34560,
  },
  delta: {
    cpu_percent: 1.2,
    memory_percent: -0.4,
    disk_percent: 0.1,
  },
  hosts: [],
}

const topology: DashboardTopology = {
  generated_at: '2026-07-25T08:00:00Z',
  nodes: [
    { id: 'controller', label: 'Controller', kind: 'control', status: 'healthy' },
    { id: 'gateway', label: 'Agent Gateway', kind: 'gateway', status: 'unknown' },
    { id: 'database', label: 'PostgreSQL', kind: 'database', status: 'healthy' },
    { id: 'web', label: 'Web', kind: 'web', status: 'healthy' },
    { id: 'agent-host-1', label: 'edge-hk', kind: 'agent', status: 'healthy' },
  ],
}

const security: DashboardSecurity = {
  generated_at: '2026-07-25T08:00:00Z',
  controls: {
    uncovered_critical: 0,
    uncovered_high: 0,
    mtls: 'enforced',
    crl: 'enforced',
    certificate_rotation: 'operational',
    last_scan_at: '2026-07-25T07:30:00Z',
    login_rate_limit: 'enforced',
    totp: 'available',
    rbac: 'enforced',
    audit: 'append_only',
  },
}

interface MockOptions {
  locale?: 'en-US' | 'zh-CN'
  theme?: 'light' | 'dark'
  bootstrapStatus?: number
  bootstrapDelay?: number
  resourceStatus?: number
}

async function mockAuthenticated(
  page: Page,
  options: MockOptions = {},
): Promise<Map<string, number>> {
  const counts = new Map<string, number>()
  await page.addInitScript(({ locale, theme }) => {
    sessionStorage.setItem('guardian_token', 'playwright-session')
    if (locale && !localStorage.getItem('guardian_locale')) localStorage.setItem('guardian_locale', locale)
    if (!localStorage.getItem('guardian_theme')) localStorage.setItem('guardian_theme', theme)
  }, { locale: options.locale, theme: options.theme ?? 'light' })
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    counts.set(path, (counts.get(path) ?? 0) + 1)
    if (path === '/api/v1/auth/me') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(user) })
      return
    }
    if (path === '/api/v1/dashboard/bootstrap') {
      if (options.bootstrapDelay) await new Promise((resolve) => setTimeout(resolve, options.bootstrapDelay))
      const failed = options.bootstrapStatus && options.bootstrapStatus >= 400
      await route.fulfill({
        status: options.bootstrapStatus ?? 200,
        contentType: 'application/json',
        body: JSON.stringify(failed ? { code: 'controller_unavailable' } : bootstrap),
      })
      return
    }
    if (path === '/api/v1/dashboard/resources/current') {
      await route.fulfill({
        status: options.resourceStatus ?? 200,
        contentType: 'application/json',
        body: JSON.stringify(options.resourceStatus ? { code: 'resource_unavailable' } : resources),
      })
      return
    }
    if (path === '/api/v1/approvals/presentation') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(approvalSummaries),
      })
      return
    }
    if (path === `/api/v1/approvals/${approvalDetail.id}/presentation`) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(approvalDetail),
      })
      return
    }
    if (path === `/api/v1/approvals/${approvalDetail.id}/evidence`) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(approvalEvidence),
      })
      return
    }
    if (path === '/api/v1/hosts/host-1/latest') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          host_id: 'host-1',
          collected_at: '2026-07-25T07:59:50Z',
          payload: {
            memory_total_bytes: 8589934592,
            memory_available_bytes: 4294967296,
            disk_total_bytes: 107374182400,
            disk_free_bytes: 53687091200,
            load_1: 0.22,
            uptime_seconds: 86400,
          },
        }),
      })
      return
    }
    if (path === '/api/v1/audit/17/evidence') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          audit_id: 17,
          action_code: 'auth.login',
          resource_type: 'session',
          resource_id: 'session-17',
          actor_id: 'user-1',
          source_ip: '172.19.0.4',
          changes: {},
          correlation_id: 'request-17',
        }),
      })
      return
    }
    const payloads: Record<string, unknown> = {
      '/api/v1/hosts': hosts,
      '/api/v1/hosts/presentation': hostPresentations,
      '/api/v1/audit/presentation': auditPresentations,
      '/api/v1/service-checks': checks,
      '/api/v1/services': observations,
      '/api/v1/service-check-results': results,
      '/api/v1/incidents': incidents,
      '/api/v1/users': [user],
      '/api/v1/dashboard/topology': topology,
      '/api/v1/dashboard/security': security,
      '/api/v1/agents': [],
      '/api/v1/alerts': [],
      '/api/v1/alert-rules': [],
      '/api/v1/notification-channels': [],
      '/api/v1/notification-deliveries': [],
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(payloads[path] ?? []),
    })
  })
  return counts
}

async function mockAnonymous(page: Page): Promise<void> {
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    await route.fulfill({
      status: path === '/api/v1/auth/me' ? 401 : 403,
      contentType: 'application/json',
      body: JSON.stringify({ code: path === '/api/v1/auth/me' ? 'not_authenticated' : 'forbidden' }),
    })
  })
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate(
    () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
  )).toBe(true)
}

async function contrastRatio(page: Page, selector: string): Promise<number> {
  return page.locator(selector).evaluate((element) => {
    const rgb = (value: string): number[] => value.match(/\d+(?:\.\d+)?/g)!.slice(0, 3).map(Number)
    const isOpaque = (value: string): boolean => {
      const alpha = value.match(/rgba?\([^)]*(?:,\s*([\d.]+))\)$/)?.[1]
      return value !== 'transparent' && (alpha == null || Number(alpha) > 0)
    }
    const effectiveBackground = (target: Element): string => {
      const own = getComputedStyle(target).backgroundColor
      if (isOpaque(own)) return own
      const paintedChild = [...target.children]
        .map((child) => getComputedStyle(child).backgroundColor)
        .find(isOpaque)
      if (paintedChild) return paintedChild
      return target.parentElement ? effectiveBackground(target.parentElement) : 'rgb(255, 255, 255)'
    }
    const luminance = (color: number[]): number => {
      const channels = color.map((value) => {
        const channel = value / 255
        return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
      })
      return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722
    }
    const style = getComputedStyle(element)
    const foreground = luminance(rgb(style.color))
    const background = luminance(rgb(effectiveBackground(element)))
    return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05)
  })
}

test('overview renders from one lightweight bootstrap without legacy heavy requests', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  const counts = await mockAuthenticated(page)
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('/overview')

  await expect(page.getByRole('heading', { name: 'Operational overview' })).toBeVisible()
  await expect(page.getByText('Not deployed', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Recoverable', { exact: true }).first()).toBeVisible()
  await expect.poll(() => counts.get('/api/v1/auth/me')).toBe(1)
  await expect.poll(() => counts.get('/api/v1/dashboard/bootstrap')).toBe(1)
  expect(counts.get('/api/v1/overview')).toBeUndefined()
  expect(counts.get('/api/v1/stability')).toBeUndefined()
  expect(errors).toEqual([])
  await expectNoHorizontalOverflow(page)
  await expect(page.getByText('28%', { exact: true })).toBeVisible()
  await capture(page, 'overview-1440-light')
})

test('topology and security use bounded summaries without the legacy overview', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  const counts = await mockAuthenticated(page)

  await page.goto('/topology')
  await expect(page.getByText('Agent Gateway', { exact: true })).toBeVisible()
  await page.goto('/security')
  await expect(page.getByText('Owner TOTP', { exact: true })).toBeVisible()

  await expect.poll(() => counts.get('/api/v1/dashboard/topology')).toBe(1)
  await expect.poll(() => counts.get('/api/v1/dashboard/security')).toBe(1)
  expect(counts.get('/api/v1/overview')).toBeUndefined()
  expect(errors).toEqual([])
})

test('active navigation remains visible in light and dark themes on key routes', async ({ page }) => {
  test.setTimeout(90_000)
  await mockAuthenticated(page)
  await page.goto('/overview')
  const allNavigationRoutes = [
    '/overview',
    '/hosts',
    '/services',
    '/topology',
    '/alerts',
    '/incidents',
    '/repairs',
    '/approvals',
    '/recovery',
    '/account-security',
    '/security',
    '/users',
    '/agents',
    '/notifications',
    '/audit',
    '/settings',
  ]
  for (const theme of ['light', 'dark'] as const) {
    const routes = allNavigationRoutes
    for (const route of routes) {
      await page.goto(route)
      const active = page.locator('.proto-navigation a[aria-current="page"]')
      await expect(active).toHaveCount(1)
      await expect(active).toBeVisible()
      expect((await active.boundingBox())!.width).toBeGreaterThan(100)
      expect(await contrastRatio(page, '.proto-navigation a[aria-current="page"]')).toBeGreaterThanOrEqual(4.5)
    }
    if (theme === 'light') {
      await page.getByRole('button', { name: 'Switch to dark mode' }).click()
      await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
    }
  }
})

test('approval center is decision-first, accessible, and does not expose raw JSON by default', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  const counts = await mockAuthenticated(page)
  await page.setViewportSize({ width: 1366, height: 900 })
  await page.goto('/approvals')

  await expect(page.getByRole('heading', { name: 'Restart service' })).toBeVisible()
  await expect(page.getByText('gateway.service')).toBeVisible()
  await expect(page.getByText('Rollback path available')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Request changes' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Approve with conditions' })).toBeVisible()
  await expect(page.getByText('approval-pending-1')).toHaveCount(0)
  await expect(page.getByText('"agent_id"')).toHaveCount(0)
  await expect.poll(() => counts.get('/api/v1/approvals/presentation')).toBe(1)
  expect(counts.get(`/api/v1/approvals/${approvalDetail.id}/evidence`)).toBeUndefined()

  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? ''))).toEqual([])
  expect(errors).toEqual([])
  await expectNoHorizontalOverflow(page)
  await capture(page, 'approvals-1366-light')

  await page.locator('.approval-evidence summary').click()
  await expect(page.locator('.approval-evidence .approval-evidence-lines').getByText('"agent_id"')).toBeVisible()
  await expect.poll(() => counts.get(`/api/v1/approvals/${approvalDetail.id}/evidence`)).toBe(1)
  await page.getByRole('button', { name: 'Request changes' }).click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.getByRole('dialog').getByText('Changes requested')).toBeVisible()
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click()
  await page.getByRole('button', { name: 'Approve execution' }).click()
  await expect(page.getByRole('dialog').getByLabel('Current password (reauthentication)')).toBeVisible()
  await expect(page.getByRole('dialog').getByText('I verified the rollback path and recovery requirements.')).toBeVisible()
})

test('approval filters and mobile master-detail behavior remain usable', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'zh-CN' })
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/approvals')

  await expect(page.getByRole('row', { name: /重启服务/ })).toBeVisible()
  await page.getByRole('row', { name: /重启服务/ }).click()
  await expect(page.getByRole('heading', { name: '重启服务' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await capture(page, 'approvals-390-detail-light')
  await page.getByRole('button', { name: '返回请求列表' }).click()
  await expect(page.getByRole('row', { name: /重启服务/ })).toBeVisible()
  await page.getByRole('searchbox', { name: '搜索审批' }).fill('worker')
  await expect(page.getByRole('row', { name: /受限清理/ })).toBeVisible()
  await expect(page.getByRole('row', { name: /重启服务/ })).toHaveCount(0)
  await expectNoHorizontalOverflow(page)
  await capture(page, 'approvals-390-list-light')
})

test('approval center dark theme and 768px detail use semantic surfaces', async ({ page }) => {
  await mockAuthenticated(page, { theme: 'dark' })
  await page.setViewportSize({ width: 768, height: 900 })
  await page.goto('/approvals')
  await expect(page.getByRole('row', { name: /Restart service/ })).toBeVisible()
  const queueBackground = await page.locator('.approval-workspace .rc5-data-region').evaluate(
    (element) => getComputedStyle(element).backgroundColor,
  )
  expect(queueBackground).not.toBe('rgb(0, 0, 0)')
  await page.getByRole('row', { name: /Restart service/ }).click()
  await expect(page.getByRole('heading', { name: 'Restart service' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? ''))).toEqual([])
  await capture(page, 'approvals-768-detail-dark')
})

test('approval route remains bounded and lazy-loads detail and evidence', async ({ page }) => {
  const counts = await mockAuthenticated(page)
  await page.goto('/overview')
  const samples: number[] = []
  for (let index = 0; index < 3; index += 1) {
    const started = performance.now()
    await page.getByRole('link', { name: 'Approvals' }).click()
    await expect(page.getByRole('heading', { name: 'Restart service' })).toBeVisible()
    samples.push(performance.now() - started)
    await page.getByRole('link', { name: 'Operations overview' }).click()
    await expect(page.getByRole('heading', { name: 'Operational overview' })).toBeVisible()
  }
  samples.sort((left, right) => left - right)
  expect(samples[1]).toBeLessThanOrEqual(300)
  expect(counts.get('/api/v1/auth/me')).toBe(1)
  expect(counts.get('/api/v1/approvals/presentation')).toBe(3)
  expect(counts.get(`/api/v1/approvals/${approvalDetail.id}/presentation`)).toBe(3)
  expect(counts.get(`/api/v1/approvals/${approvalDetail.id}/evidence`)).toBeUndefined()
})

test('desktop navigation collapse persists and expansion restores visible labels', async ({ page }) => {
  await mockAuthenticated(page)
  await page.goto('/services')
  const active = page.locator('.proto-navigation a[aria-current="page"]')
  const activeLabel = active.locator('span')
  await expect(activeLabel).toBeVisible()
  const label = (await activeLabel.textContent())!.trim()
  await page.getByRole('button', { name: 'Collapse navigation' }).click()
  await expect(page.locator('.proto-app')).toHaveClass(/sidebar-collapsed/)
  await expect(active).toHaveAttribute('title', label)
  await page.reload()
  await expect(page.locator('.proto-app')).toHaveClass(/sidebar-collapsed/)
  await page.getByRole('button', { name: 'Expand navigation' }).click()
  await expect(activeLabel).toBeVisible()
  await expect(active).not.toHaveAttribute('title')
})

test('command palette is keyboard accessible and navigates without losing shell context', async ({ page }) => {
  await mockAuthenticated(page)
  await page.goto('/overview')
  await expect(page.getByRole('heading', { name: 'Operational overview' })).toBeVisible()
  await page.keyboard.press('Control+K')
  const palette = page.getByRole('dialog', { name: 'Search and navigate' })
  await expect(palette).toBeVisible()
  const input = palette.getByPlaceholder('Search pages and actions…')
  await expect(input).toBeFocused()
  await input.fill('incident')
  await palette.getByRole('button', { name: /Incidents/ }).click()
  await expect(page).toHaveURL(/\/incidents$/)
  await expect(page.getByRole('heading', { name: 'Incidents' })).toBeVisible()
})

test('services uses structured rows and treats zero failed systemd units as healthy', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'zh-CN', theme: 'light' })
  await page.goto('/services')
  await expect(page.getByRole('heading', { name: '服务检查' })).toBeVisible()
  await expect(page.getByText('未发现失败的 systemd unit')).toBeVisible()
  await expect(page.locator('pre')).toHaveCount(0)
  await page.getByText('未发现失败的 systemd unit').click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.locator('pre')).toHaveCount(0)
  await capture(page, 'services-1440-light-detail-zh')
})

test('services filters persist in the URL and audited batch controls are usable', async ({ page }) => {
  const counts = await mockAuthenticated(page)
  await page.goto('/services')
  await page.getByRole('combobox', { name: 'Type' }).selectOption('systemd')
  await expect(page).toHaveURL(/kind=systemd/)
  await page.getByRole('checkbox', { name: /Select .*Failed/i }).check()
  await expect(page.getByText('1 selected')).toBeVisible()
  await page.getByRole('button', { name: 'Disable' }).click()
  await expect.poll(() => counts.get('/api/v1/service-checks/check-2')).toBe(1)
  await expect(page.getByText('1 selected')).toHaveCount(0)
})

test('raw evidence is escaped, collapsed by default, and exposes controlled viewer actions', async ({ page }) => {
  await mockAuthenticated(page)
  await page.goto('/services')
  await page.getByText('No failed systemd units').click()
  await expect(page.getByText('View raw evidence')).toBeVisible()
  await expect(page.locator('.proto-evidence')).toHaveCount(0)
  await page.getByText('View raw evidence').click()
  await expect(page.locator('.proto-evidence')).toBeVisible()
  await expect(page.locator('.proto-evidence img')).toHaveCount(0)
  await expect(page.locator('.proto-evidence code')).toContainText('<img src=x')
  await expect(page.getByRole('button', { name: 'Copy' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Full screen' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Download redacted' })).toBeVisible()
  expect(await page.evaluate(() => (globalThis as { __evidenceInjected?: boolean }).__evidenceInjected)).not.toBe(true)
})

test('incidents omits fake confidence, labels tests, and keeps selected-row contrast', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'zh-CN', theme: 'light' })
  await page.goto('/incidents')
  await expect(page.getByRole('heading', { name: '事故' })).toBeVisible()
  await expect(page.locator('.proto-test-label', { hasText: '测试记录' })).toBeVisible()
  await expect(page.getByText('0%', { exact: true })).toHaveCount(0)
  await page.getByText('后端服务不可用').first().click()
  const selected = page.locator('.incidents-table tr.selected')
  await expect(selected).toBeVisible()
  expect(await contrastRatio(page, '.incidents-table tr.selected')).toBeGreaterThanOrEqual(4.5)
  await expect(page.getByRole('dialog')).toBeVisible()
  await capture(page, 'incidents-1440-light-detail-zh')
})

test('incident severity, owner, source and record filters persist in the URL', async ({ page }) => {
  await mockAuthenticated(page)
  await page.goto('/incidents')
  await page.getByRole('combobox', { name: 'Severity' }).selectOption('3')
  await page.getByRole('combobox', { name: 'Owner' }).selectOption(user.id)
  await expect(page).toHaveURL(/severity=3/)
  await expect(page).toHaveURL(/owner=user-1/)
  await expect(page.getByText('Reverse proxy backend requires attention')).toBeVisible()
  await page.getByRole('combobox', { name: 'Record type' }).selectOption('test')
  await expect(page).toHaveURL(/record=test/)
  await expect(page.getByText('No incidents match the current filters.')).toBeVisible()
})

test('resource summary loads independently and its failure does not blank overview', async ({ page }) => {
  const counts = await mockAuthenticated(page, { resourceStatus: 503 })
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('/overview')
  await expect(page.getByRole('heading', { name: 'Operational overview' })).toBeVisible()
  await page.getByRole('button', { name: 'Load resource trends' }).click()
  await expect(page.getByText('Resource summary failed; the operational summary remains available.')).toBeVisible()
  expect(counts.get('/api/v1/dashboard/resources/current')).toBeGreaterThanOrEqual(1)
  await expect(page.getByRole('heading', { name: 'Operational overview' })).toBeVisible()
})

test('anonymous and stale sessions are quiet, single-shot, and preserve deep links', async ({ page }) => {
  const errors: string[] = []
  let meRequests = 0
  page.on('pageerror', (error) => errors.push(error.message))
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === '/api/v1/auth/me') meRequests += 1
  })
  await mockAnonymous(page)
  await page.goto('/users')
  await expect(page).toHaveURL(/\/login\?redirect=\/users$/)
  await expect.poll(() => meRequests).toBe(1)
  expect(errors).toEqual([])
})

test('non-401 auth restore failure is explicit and produces no unhandled rejection', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.route('**/api/v1/**', async (route) => {
    await route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ code: 'auth_unavailable' }),
    })
  })
  await page.goto('/overview')
  await expect(page.getByRole('heading', { name: 'Unable to restore session' })).toBeVisible()
  expect(errors).toEqual([])
})

test('login and logout return to a protected, quiet signed-out state', async ({ page }) => {
  let authenticated = false
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/auth/me') {
      await route.fulfill({
        status: authenticated ? 200 : 401,
        contentType: 'application/json',
        body: JSON.stringify(authenticated ? user : { code: 'not_authenticated' }),
      })
      return
    }
    if (path === '/api/v1/auth/login') {
      authenticated = true
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          access_token: 'new-session',
          csrf_token: 'new-csrf',
          identity_setup_required: false,
          recovery_codes_remaining: null,
        }),
      })
      return
    }
    if (path === '/api/v1/auth/logout') {
      authenticated = false
      await route.fulfill({ status: 204, body: '' })
      return
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(path === '/api/v1/dashboard/bootstrap' ? bootstrap : []),
    })
  })
  await page.goto('/login')
  await page.locator('input[type="email"]').fill(user.email)
  await page.locator('input[type="password"]').fill('browser-only-password')
  await page.locator('button[type="submit"]').click()
  await expect(page).toHaveURL(/\/overview$/)
  await expect(page.getByRole('heading', { name: 'Operational overview' })).toBeVisible()
  await page.locator('.proto-sidebar-footer > button').click()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login$/)
  await page.goto('/overview')
  await expect(page).toHaveURL(/\/login\?redirect=\/overview$/)
  expect(errors).toEqual([])
})

test('mobile overview, services and incidents have no document overflow', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'zh-CN', theme: 'light' })
  await page.setViewportSize({ width: 390, height: 844 })
  for (const route of ['/overview', '/services', '/incidents']) {
    await page.goto(route)
    await expect(page.locator('.proto-page-header h1')).toBeVisible()
    await expectNoHorizontalOverflow(page)
    await capture(page, `${route.slice(1)}-390-light-zh`)
  }
})

test('mobile navigation locks background, closes with Escape, and returns focus', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'zh-CN', theme: 'light' })
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/overview')
  const trigger = page.getByRole('button', { name: '打开导航' })
  await trigger.click()
  await expect(page.locator('body')).toHaveClass(/prototype-lock-scroll/)
  await expect(page.getByRole('button', { name: '关闭导航' })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(page.locator('body')).not.toHaveClass(/prototype-lock-scroll/)
  await expect(trigger).toBeFocused()
})

test('locale and theme controls persist after reload', async ({ page }) => {
  await mockAuthenticated(page, { theme: 'dark' })
  await page.goto('/overview')
  await page.locator('.proto-locale-button').click()
  await expect(page.getByRole('heading', { name: '运行概览' })).toBeVisible()
  await page.getByRole('button', { name: '切换到亮色模式' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await page.reload()
  await expect(page.getByRole('heading', { name: '运行概览' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
})

test('critical V3 routes have no serious axe accessibility violations', async ({ page }) => {
  await mockAuthenticated(page, { theme: 'light' })
  for (const route of ['/overview', '/services', '/incidents']) {
    await page.goto(route)
    await expect(page.locator('.proto-page-header h1')).toBeVisible()
    const results = await new AxeBuilder({ page }).analyze()
    expect(
      results.violations
        .filter((violation) => ['critical', 'serious'].includes(violation.impact ?? ''))
        .map((violation) => ({
          id: violation.id,
          impact: violation.impact,
          targets: violation.nodes.map((node) => node.target),
        })),
    ).toEqual([])
  }
})

test('critical Chinese routes expose no object coercion or raw null markers', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'zh-CN', theme: 'light' })
  for (const route of ['/overview', '/services', '/incidents']) {
    await page.goto(route)
    const body = await page.locator('body').innerText()
    expect(body).not.toContain('[object Object]')
    expect(body).not.toMatch(/\bundefined\b/)
    expect(body).not.toMatch(/\bnull\b/)
    expect(body).not.toContain('incident is open')
    expect(body).not.toContain('Gateway requests may fail')
    expect(body).not.toContain('Investigation started')
    expect(body).not.toContain('Check passed')
  }
})

test('RC5 hosts uses semantic selection, compact mobile records, and an accessible detail drawer', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'en-US', theme: 'light' })
  await page.setViewportSize({ width: 1366, height: 900 })
  await page.goto('/hosts')
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()
  await expect(page.getByRole('table', { name: 'Hosts' }).getByText('Guardian + Komari')).toBeVisible()
  await expect(page.getByRole('table', { name: 'Hosts' }).getByText('Reporting')).toBeVisible()
  await expect(page.getByText('komari-import')).toHaveCount(0)
  await expect(page.getByRole('table', { name: 'Hosts' })).not.toContainText('192.0.2.10')
  await expect(page.getByRole('table', { name: 'Hosts' })).not.toContainText('komari:')
  await page.getByRole('row', { name: /edge-hk/ }).click()
  const selected = page.getByRole('row', { name: /edge-hk/ })
  await expect(selected).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByRole('dialog', { name: 'edge-hk' })).toBeVisible()
  const background = await selected.evaluate((element) => getComputedStyle(element).backgroundColor)
  expect(background).not.toBe('rgb(14, 18, 22)')
  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? ''))).toEqual([])
  await expectNoHorizontalOverflow(page)
  await capture(page, 'rc5-hosts-drawer-1366-light')

  await page.getByRole('button', { name: /close/i }).click()
  await page.setViewportSize({ width: 390, height: 844 })
  await expectNoHorizontalOverflow(page)
  await expect(page.getByRole('row', { name: /edge-hk/ })).toBeVisible()
  await capture(page, 'rc5-hosts-390-light')
})

test('RC5 audit keeps machine evidence out of the primary table and reveals it only on demand', async ({ page }) => {
  const counts = await mockAuthenticated(page, { locale: 'zh-CN', theme: 'light' })
  await page.setViewportSize({ width: 1366, height: 900 })
  await page.goto('/audit')
  await expect(page.getByText('用户登录')).toBeVisible()
  await expect(page.getByText('Controller 内部服务')).toBeVisible()
  await expect(page.getByText('auth.login')).not.toBeVisible()
  await expect(page.getByText('172.19.0.4')).toHaveCount(0)
  await page.getByRole('row', { name: /用户登录/ }).click()
  await expect(page.getByRole('dialog', { name: '用户登录' })).toBeVisible()
  expect(counts.get('/api/v1/audit/17/evidence') ?? 0).toBe(0)
  await expect(page.getByText('auth.login')).not.toBeVisible()
  await page.getByText('技术证据', { exact: true }).click()
  await expect.poll(() => counts.get('/api/v1/audit/17/evidence')).toBe(1)
  await expect(page.getByText('auth.login')).toBeVisible()
  await expect(page.getByText('172.19.0.4')).toBeVisible()
  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? ''))).toEqual([])
  await expectNoHorizontalOverflow(page)
  await capture(page, 'rc5-audit-drawer-1366-light')
})

test('Chinese primary surfaces reject raw machine values across the product routes', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'zh-CN', theme: 'light' })
  const routes = [
    '/overview', '/hosts', '/services', '/topology', '/alerts', '/incidents',
    '/repairs', '/approvals', '/backup', '/account-security', '/security',
    '/users', '/agents', '/notifications', '/audit', '/settings',
  ]
  const forbidden = [
    /\b(?:auth|session|host|notification|approval)\.[a-z_]+\b/i,
    /\b(?:pending_enrollment|komari-import|restricted_cleanup)\b/i,
    /\b(?:true|false|null|undefined)\b/i,
    /\[object Object\]/i,
    /\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/,
  ]
  for (const route of routes) {
    await page.goto(route)
    await page.waitForLoadState('networkidle')
    const text = await page.locator('main').innerText()
    for (const pattern of forbidden) expect(text, `${route} exposes ${pattern}`).not.toMatch(pattern)
  }
})

test('all tabular product surfaces use the shared RC5 DataTable region', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'en-US', theme: 'light' })
  const routes = [
    '/hosts',
    '/services',
    '/alerts',
    '/incidents',
    '/approvals',
    '/users',
    '/agents',
    '/notifications',
    '/audit',
    '/backup',
    '/account-security',
  ]
  for (const route of routes) {
    await page.goto(route)
    await expect(page.locator('.rc5-data-region').first(), `${route} did not mount the shared DataTable`).toBeVisible()
    const width = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth,
      client: document.documentElement.clientWidth,
      offenders: [...document.querySelectorAll<HTMLElement>('body *')]
        .map((element) => ({ element, rect: element.getBoundingClientRect() }))
        .filter(({ rect }) => rect.right > document.documentElement.clientWidth + 1)
        .slice(0, 5)
        .map(({ element, rect }) => ({
          tag: element.tagName,
          className: element.className,
          right: Math.round(rect.right),
          width: Math.round(rect.width),
        })),
    }))
    expect(width.scroll, `${route} overflowed its ${width.client}px viewport: ${JSON.stringify(width.offenders)}`).toBeLessThanOrEqual(width.client)
  }
})

test('200 percent zoom equivalent reflows critical data routes without clipping', async ({ page }) => {
  await mockAuthenticated(page, { locale: 'zh-CN', theme: 'light' })
  await page.setViewportSize({ width: 683, height: 450 })
  for (const route of ['/hosts', '/audit', '/approvals']) {
    await page.goto(route)
    await expect(page.locator('.rc5-data-region').first()).toBeVisible()
    await expectNoHorizontalOverflow(page)
  }
})

test('shared selected rows remain readable in light, dark, hover, focus, and reduced motion', async ({ page }) => {
  test.setTimeout(60_000)
  await mockAuthenticated(page, { locale: 'en-US', theme: 'light' })
  const cases = [
    { path: '/services', row: '.services-table tbody tr', selected: '.services-table tbody tr.selected' },
    { path: '/incidents', row: '.incidents-table tbody tr', selected: '.incidents-table tbody tr.selected' },
    { path: '/approvals', row: '.approval-row', selected: '.approval-row.selected' },
    { path: '/hosts', row: '.rc5-data-table tbody tr', selected: '.rc5-data-table tbody tr.is-selected' },
    { path: '/audit', row: '.rc5-data-table tbody tr', selected: '.rc5-data-table tbody tr.is-selected' },
  ]
  await page.emulateMedia({ reducedMotion: 'reduce' })
  for (const theme of ['light', 'dark'] as const) {
    if (theme === 'dark') {
      await page.evaluate(() => localStorage.setItem('guardian_theme', 'dark'))
    }
    for (const item of cases) {
      await page.goto(item.path)
      await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme)
      const row = page.locator(item.row).first()
      await expect(row).toBeVisible()
      await row.click()
      const selected = page.locator(item.selected).first()
      await expect(selected).toBeVisible()
      const colors = await selected.evaluate((element) => {
        const style = getComputedStyle(element)
        return { background: style.backgroundColor, color: style.color }
      })
      expect(colors.background).not.toMatch(/rgb\((?:0|1[0-9]|2[0-5]),\s*(?:0|1[0-9]|2[0-5]),\s*(?:0|1[0-9]|2[0-5])\)/)
      expect(await contrastRatio(page, item.selected), `${theme} ${item.path} ${JSON.stringify(colors)}`).toBeGreaterThanOrEqual(4.5)
      await selected.hover({ force: true })
      expect((await selected.evaluate((element) => getComputedStyle(element).backgroundColor))).not.toBe('rgb(14, 18, 22)')
      if (await selected.getAttribute('tabindex')) {
        await selected.focus()
        await expect(selected).toBeFocused()
      }
    }
  }
})
