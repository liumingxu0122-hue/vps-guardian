// Archived Phase 4 V2 browser coverage; UI V3 coverage lives in visual.spec.ts.
import { expect, test, type Page } from '@playwright/test'

import type {
  Alert,
  AlertRule,
  AttentionResponse,
  Host,
  NotificationChannel,
  NotificationDelivery,
  Overview,
  PublicSettings,
  ServiceCheck,
  StabilityReport,
  User,
} from '../src/types'

const user: User = {
  id: 'user-1',
  email: 'owner@example.test',
  role: 'owner',
  totp_enabled: true,
  is_active: true,
  scopes: [],
  last_login_at: '2026-07-21T07:30:00Z',
  disabled_at: null,
  created_at: '2026-07-01T00:00:00Z',
}
const points = Array.from({ length: 12 }, (_, index) => ({
  at: new Date(Date.UTC(2026, 6, 21, index * 2)).toISOString(),
  cpu_percent: 18 + index * 2,
  cpu_source: 'cpu_time' as const,
  memory_percent: 42 + index,
  disk_percent: 67 + index * 1.5,
  network_bytes_per_second: 24_000 + index * 1_200,
}))

const overview: Overview = {
  generated_at: '2026-07-21T08:00:00Z',
  environment: {
    current: 'staging',
    production_deployed: false,
    production_status: 'not_deployed',
    gate_decision: 'go_for_controlled_production_rollout_planning',
    version: '0.4.0-phase4-preview',
    deployment_commit: 'b'.repeat(40),
    deployed_at: '2026-07-21T06:00:00Z',
  },
  global_health: 'degraded',
  health_reasons: [{ severity: 'warning', reason: 'one host needs attention', object: 'staging-agent' }],
  attention: [{
    id: 'certificate:host-2',
    type: 'certificate_expiry',
    severity: 'warning',
    object: 'staging-agent',
    reason: 'Agent certificate expires within 14 days',
    observed_at: '2026-07-21T07:58:20Z',
    duration_seconds: 90,
    suggested_action: 'Review certificate rotation',
    href: '/agents',
  }],
  hosts: { total: 2, inventory_total: 2, unregistered: 0, disabled: 0, healthy: 1, degraded: 1, offline: 0, unknown: 0 },
  checks: { total: 1, enabled: 1, healthy: 0, failed: 1, unknown: 0 },
  agent_versions: { '0.3.0-alpha.1': 2 },
  expiring_certificates: 1,
  incidents: { open: 2, critical: 1 },
  alerts: { active: 2, critical: 1, warning: 1 },
  pending_approvals: 1,
  verified_recovery_points: 1,
  notification_failures: 1,
  recent_incidents: [],
  recovery: {
    repository: 'R2 Restic',
    status: 'healthy',
    accepted_snapshot: 'a492e73f5698',
    last_backup_at: '2026-07-20T18:27:34Z',
    last_check_at: '2026-07-21T07:50:00Z',
    snapshot_count: 4,
    restore_status: 'passed',
    retention_policy: 'approval_required_no_forget_or_prune',
    rpo_seconds: 16,
    rto_seconds: 50,
    measurement_scope: 'staging_measured',
  },
  security: {
    uncovered_critical: 0,
    uncovered_high: 0,
    mtls: 'enforced',
    crl: 'enforced',
    certificate_rotation: 'operational',
    last_scan_at: '2026-07-20T06:00:00Z',
    login_rate_limit: 'enforced',
    totp: 'available',
    rbac: 'enforced',
    audit: 'append_only',
  },
  permissions: {
    role: 'owner',
    can_view_recovery: true,
    can_view_security: true,
    can_approve: true,
    dangerous_actions: 'approval_required',
  },
  resource_window: '24h',
  resource_series: { 'host-1': points, 'host-2': points.map((point) => ({ ...point, cpu_percent: point.cpu_percent + 8 })) },
  resource_series_truncated: false,
  host_rows: [
    {
      id: 'host-1',
      name: 'staging-controller',
      location: 'Hong Kong',
      group: 'control',
      tags: ['staging'],
      data_state: 'normal',
      enabled: true,
      status: 'healthy',
      last_heartbeat_at: '2026-07-21T07:59:45Z',
      agent_serial: '1008',
      certificate_status: 'valid',
      certificate_expires_at: '2026-10-21T00:00:00Z',
      agent_version: '0.3.0-alpha.1',
      offline_queue: 0,
      failed_tasks: 0,
      queued_tasks: 0,
      resources: { cpu_percent: 31.2, cpu_source: 'cpu_time', memory_percent: 48.1, disk_percent: 68.4, network_bytes_per_second: 34_200, collected_at: '2026-07-21T07:59:45Z' },
    },
    {
      id: 'host-2',
      name: 'staging-agent',
      location: 'Singapore',
      group: 'edge',
      tags: ['staging', 'linux'],
      data_state: 'stale',
      enabled: true,
      status: 'degraded',
      last_heartbeat_at: '2026-07-21T07:58:20Z',
      agent_serial: '1012',
      certificate_status: 'expiring',
      certificate_expires_at: '2026-08-01T00:00:00Z',
      agent_version: '0.3.0-alpha.1',
      offline_queue: 3,
      failed_tasks: 1,
      queued_tasks: 1,
      resources: { cpu_percent: 44.8, cpu_source: 'cpu_time', memory_percent: 62.5, disk_percent: 91.2, network_bytes_per_second: 41_100, collected_at: '2026-07-21T07:58:20Z' },
    },
  ],
  topology: [
    { id: 'controller', label: 'Controller', kind: 'control', status: 'healthy' },
    { id: 'haproxy', label: 'HAProxy', kind: 'gateway', status: 'healthy' },
    { id: 'postgresql', label: 'PostgreSQL', kind: 'database', status: 'healthy' },
    { id: 'web', label: 'Web', kind: 'web', status: 'healthy' },
    { id: 'agent-host-1', label: 'staging-controller', kind: 'agent', status: 'healthy' },
    { id: 'agent-host-2', label: 'staging-agent', kind: 'agent', status: 'degraded' },
  ],
  timeline: [
    { id: 'incident-1', kind: 'incident', severity: 4, host_id: 'host-2', title: 'Gateway health degraded', status: 'investigating', at: '2026-07-21T07:45:00Z' },
    { id: 'repair-1', kind: 'repair', severity: 1, host_id: 'host-1', title: 'validated recovery path', status: 'passed', at: '2026-07-21T07:30:00Z' },
  ],
}

const stability: StabilityReport = {
  generated_at: overview.generated_at,
  window: '24h',
  formula_version: 1,
  expected_heartbeat_interval_seconds: 60,
  hosts: [
    {
      host_id: 'host-1',
      host_name: 'staging-controller',
      group: 'control',
      location: 'Hong Kong',
      status: 'scored',
      reason: 'sufficient evidence',
      stability_score: 96.2,
      uptime_score: 99.8,
      heartbeat_score: 98.4,
      check_success_score: 95.0,
      failure_rate: 0.05,
      mean_recovery_time: 180,
      stale_ratio: 0.01,
      alert_frequency: 0.04,
      confidence: 0.92,
      sample_count: 1440,
      check_count: 720,
      is_new: false,
    },
    {
      host_id: 'host-2',
      host_name: 'staging-agent',
      group: 'edge',
      location: 'Singapore',
      status: 'scored',
      reason: 'intermittent check failures',
      stability_score: 78.4,
      uptime_score: 92.0,
      heartbeat_score: 88.0,
      check_success_score: 72.0,
      failure_rate: 0.28,
      mean_recovery_time: 540,
      stale_ratio: 0.08,
      alert_frequency: 0.2,
      confidence: 0.83,
      sample_count: 1320,
      check_count: 700,
      is_new: false,
    },
  ],
  aggregates: [
    { group: 'control', location: 'Hong Kong', host_count: 1, scored_count: 1, stability_score: 96.2, uptime_score: 99.8, check_success_score: 95.0 },
    { group: 'edge', location: 'Singapore', host_count: 1, scored_count: 1, stability_score: 78.4, uptime_score: 92.0, check_success_score: 72.0 },
  ],
}

const attention: AttentionResponse = {
  generated_at: overview.generated_at,
  global_health: overview.global_health,
  health_reasons: overview.health_reasons,
  items: overview.attention,
}

const hosts: Host[] = [{ id: 'host-1', name: 'edge-hk', address: '192.0.2.10', os_name: 'Ubuntu 24.04', location: 'Hong Kong', status: 'healthy', data_state: 'normal', enabled: true, group_name: 'edge', tags: ['linux', 'production'], labels: {}, last_seen_at: '2026-07-21T07:59:45Z', enrolled_at: '2026-07-20T00:00:00Z', disabled_at: null }]
const checks: ServiceCheck[] = [{ id: 'check-1', name: 'public-api', kind: 'https', enabled: true, host_id: 'host-1', runner_agent_id: null, configuration: { target: 'https://example.test/health' }, group_name: 'api', interval_seconds: 60, timeout_seconds: 5, failure_threshold: 3, recovery_threshold: 2, severity: 'critical', last_checked_at: '2026-07-21T07:59:45Z', created_at: '2026-07-20T00:00:00Z', updated_at: '2026-07-21T07:59:45Z' }]
const alertRules: AlertRule[] = [{ id: 'rule-1', name: 'service-public-api', enabled: true, source_type: 'service_check', source_id: 'check-1', severity: 'critical', group_key: 'api', failure_threshold: 3, recovery_threshold: 2, repeat_interval_seconds: 3600, escalation_after_seconds: null, recovery_notifications: true, created_at: '2026-07-20T00:00:00Z' }]
const alerts: Alert[] = [{ id: 'alert-1', rule_id: 'rule-1', fingerprint: 'a'.repeat(64), state: 'firing', consecutive_failures: 3, consecutive_successes: 0, first_observed_at: '2026-07-21T07:55:00Z', last_observed_at: '2026-07-21T07:59:45Z', fired_at: '2026-07-21T07:57:00Z', acknowledged_at: null, acknowledged_by: null, assigned_to: null, silenced_until: null, resolved_at: null, closed_at: null, last_notified_at: '2026-07-21T07:57:00Z', notification_count: 1, summary: 'HTTP status 503', details: {} }]
const channels: NotificationChannel[] = [{ id: 'channel-1', name: 'local-mock', kind: 'webhook', enabled: true, configuration: { endpoint_env: 'GUARDIAN_TEST_WEBHOOK_URL' }, event_scope: ['alert.firing', 'alert.recovered'], severity_filter: ['critical'], retry_policy: { max_attempts: 3, base_delay_seconds: 30 }, rate_limit_per_minute: 30, created_at: '2026-07-20T00:00:00Z' }]
const deliveries: NotificationDelivery[] = [{
  id: 'delivery-1',
  channel_id: 'channel-1',
  alert_id: 'alert-1',
  event_type: 'alert.firing',
  status: 'dead_letter',
  attempt_count: 3,
  next_attempt_at: '2026-07-21T08:05:00Z',
  delivered_at: null,
  response_code: 503,
  error_summary: 'remote endpoint unavailable',
  created_at: '2026-07-21T07:57:00Z',
}]
const publicSettings: PublicSettings = {
  environment: 'staging',
  deployment_stage: 'staging',
  release_version: '0.4.0-phase4-preview',
  deployment_commit: 'b'.repeat(40),
  deployed_at: '2026-07-21T06:00:00Z',
  secure_cookies: true,
  auto_create_schema: false,
  allowed_origins: ['https://guardian.example.test'],
  max_incident_log_bytes: 2_000_000,
  login_attempts_per_10m: 5,
  nonce_ttl_seconds: 300,
  agent_offline_after_seconds: 90,
  agent_pending_identity_ttl_minutes: 15,
  approval_ttl_minutes: 30,
  metric_retention_days: 7,
  service_result_retention_days: 30,
  max_metric_rows_per_host: 10080,
  max_results_per_check: 43200,
  external_notifications_enabled: false,
  settings_catalog: [{ key: 'metric_retention_days', value: 7, source: 'environment', restart_required: true, risk: 'medium' }],
  secret_status: { session_signing: true, field_encryption: true },
  features: { mtls: true, persistent_alerts: true },
}

interface MockOptions {
  payload?: Overview
  overviewStatus?: number
  delayMs?: number
  theme?: 'light' | 'dark'
  locale?: 'en-US' | 'zh-CN'
}

async function mockController(page: Page, options: MockOptions = {}): Promise<void> {
  await page.addInitScript(({ theme, locale }) => {
    sessionStorage.setItem('guardian_token', 'browser-test-session')
    localStorage.setItem('guardian_theme', theme)
    if (locale) localStorage.setItem('guardian_locale', locale)
  }, { theme: options.theme ?? 'dark', locale: options.locale })
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/auth/me') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(user) })
      return
    }
    if (path === '/api/v1/overview') {
      if (options.delayMs) await new Promise((resolve) => setTimeout(resolve, options.delayMs))
      await route.fulfill({
        status: options.overviewStatus ?? 200,
        contentType: 'application/json',
        body: JSON.stringify(options.overviewStatus ? { code: 'controller_unavailable' } : options.payload ?? overview),
      })
      return
    }
    if (path === '/api/v1/stability') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(stability) })
      return
    }
    const payloads: Record<string, unknown> = {
      '/api/v1/attention': attention,
      '/api/v1/hosts': hosts,
      '/api/v1/service-checks': checks,
      '/api/v1/services': [],
      '/api/v1/alerts': alerts,
      '/api/v1/alert-rules': alertRules,
      '/api/v1/agents': [],
      '/api/v1/notification-channels': channels,
      '/api/v1/notification-deliveries': deliveries,
      '/api/v1/users': [user],
      '/api/v1/settings/public': publicSettings,
    }
    if (path in payloads) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(payloads[path]) })
      return
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
  })
}

async function mockUnauthenticated(page: Page): Promise<void> {
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
  const dimensions = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }))
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth)
}

test('desktop overview renders API data in dark mode', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  await mockController(page, { theme: 'dark' })
  await page.goto('/overview')
  await expect(page.getByRole('heading', { name: 'Operations Overview' })).toBeVisible()
  await expect(page.getByText('Production · Not deployed', { exact: true })).toBeVisible()
  await expect(page.getByText('a492e73f5698', { exact: true }).first()).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: '../docs/assets/dashboard-en.png', fullPage: true })
})

test('Chinese desktop overview uses the same data and dark theme', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  await mockController(page, { theme: 'dark', locale: 'zh-CN' })
  await page.goto('/overview')
  await expect(page.getByText('允许受控生产规划')).toBeVisible()
  await expect(page.locator('.ops-host-name strong').filter({ hasText: 'staging-controller' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: '../docs/assets/dashboard-zh-CN.png', fullPage: true })
})

test('theme control switches between light and dark', async ({ page }) => {
  await mockController(page, { theme: 'dark' })
  await page.goto('/overview')
  await page.getByRole('button', { name: 'Switch to light mode' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await expect(page.getByRole('button', { name: 'Switch to dark mode' })).toBeVisible()
})

test('keyboard navigation exposes named landmarks and command palette', async ({ page }) => {
  await mockController(page)
  await page.goto('/overview')
  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible()
  await page.keyboard.press('Control+K')
  const palette = page.getByRole('dialog', { name: 'Search and navigate' })
  await expect(palette).toBeVisible()
  await expect(palette.getByPlaceholder('Search pages and actions…')).toBeFocused()
  await page.keyboard.type('notification')
  await expect(palette.getByRole('button', { name: /Notification center/ })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(palette).toBeHidden()

  const unnamedControls = await page.locator('button:visible, a:visible, select:visible, input:visible').evaluateAll((elements) =>
    elements.filter((element) => {
      const label = element.getAttribute('aria-label')
        ?? element.getAttribute('title')
        ?? element.textContent
        ?? (element as HTMLInputElement).placeholder
      return !label.trim()
    }).length,
  )
  expect(unnamedControls).toBe(0)
})

test('loading and API failure states are explicit', async ({ page }) => {
  await mockController(page, { delayMs: 700 })
  const overviewResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/v1/overview',
  )
  await page.goto('/overview')
  await expect(page.getByLabel('Loading operations overview')).toBeVisible()
  await overviewResponse
  await expect(page.getByRole('heading', { name: 'Operations Overview' })).toBeVisible()

  await page.unroute('**/api/v1/**')
  await mockController(page, { overviewStatus: 503 })
  await page.reload()
  await expect(page.getByRole('alert')).toContainText('Controller API is unavailable')
})

test('empty and restricted states do not expose actions', async ({ page }) => {
  const restricted: Overview = {
    ...overview,
    hosts: { total: 0, inventory_total: 0, unregistered: 0, disabled: 0, healthy: 0, degraded: 0, offline: 0, unknown: 0 },
    host_rows: [],
    resource_series: {},
    topology: overview.topology.filter((node) => node.kind !== 'agent'),
    timeline: [],
    permissions: {
      role: 'viewer',
      can_view_recovery: false,
      can_view_security: false,
      can_approve: false,
      dangerous_actions: 'approval_required',
    },
  }
  await mockController(page, { payload: restricted })
  await page.goto('/overview')
  await expect(page.getByText('No resource samples in this scope')).toBeVisible()
  await expect(page.getByText('No VPS hosts enrolled')).toBeVisible()
  await expect(page.getByText('Detailed recovery operations require Operator access.')).toBeVisible()
  await expect(page.getByText('Security details require Admin access.')).toBeVisible()
  await expect(page.getByRole('button', { name: /删除|forget|prune|恢复|重启|轮换/i })).toHaveCount(0)
})

test('language selection persists after reload', async ({ page }) => {
  await mockController(page)
  await page.goto('/overview')
  const selector = page.getByRole('combobox', { name: 'Language' })
  await selector.selectOption('zh-CN')
  await expect(page.getByRole('heading', { name: '运营总览' })).toBeVisible()
  await page.reload()
  await expect(page.getByRole('combobox', { name: '语言' })).toHaveValue('zh-CN')
})

test('Chinese browser locale is selected on first visit', async ({ browser }) => {
  const context = await browser.newContext({ locale: 'zh-CN' })
  const page = await context.newPage()
  await mockController(page)
  await page.goto('/overview')
  await expect(page.getByRole('heading', { name: '运营总览' })).toBeVisible()
  await context.close()
})

test('multi-VPS monitoring pages render persistent API data', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  await mockController(page)
  await page.goto('/hosts')
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()
  await expect(page.getByText('edge-hk', { exact: true })).toBeVisible()
  await expect(page.getByText('Normal', { exact: true })).toBeVisible()
  await expectNoHorizontalOverflow(page)

  await page.goto('/services')
  await expect(page.getByRole('heading', { name: 'Services' })).toBeVisible()
  await expect(page.getByText('public-api', { exact: true })).toBeVisible()

  await page.goto('/alerts')
  await expect(page.getByRole('heading', { name: 'Alerts' })).toBeVisible()
  await expect(page.getByText('HTTP status 503')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Acknowledge' })).toBeVisible()

  await page.goto('/settings')
  await expect(page.getByText('local-mock', { exact: true })).toBeVisible()
  await expect(page.getByText('7 days / 10080')).toBeVisible()
})

test('Phase 4 attention, access, and notification workflows remain structured', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 })
  await mockController(page)

  await page.goto('/attention')
  await expect(page.getByRole('heading', { name: 'Needs attention' })).toBeVisible()
  await expect(page.getByText('Agent certificate expires within 14 days')).toBeVisible()
  await expect(page.getByRole('link', { name: /Open/ })).toBeVisible()
  await expectNoHorizontalOverflow(page)

  await page.goto('/users')
  await expect(page.getByRole('heading', { name: 'Users & access' })).toBeVisible()
  await expect(page.getByRole('main').getByText('owner@example.test')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Revoke sessions' })).toBeVisible()

  await page.goto('/notifications')
  await expect(page.getByRole('heading', { name: 'Notification center' })).toBeVisible()
  await expect(page.getByText('remote endpoint unavailable')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
})

test('VPS aliases require login and preserve deep links after refresh', async ({ page }) => {
  await mockUnauthenticated(page)
  await page.goto('/vps')
  await expect(page).toHaveURL(/\/login\?redirect=\/vps$/)

  await page.unroute('**/api/v1/**')
  await mockController(page)
  await page.goto('/vps/host-1')
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()
  await expect(page.getByText('edge-hk', { exact: true })).toBeVisible()
  await expect(page).toHaveURL(/\/vps\/host-1$/)
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()
  await expect(page).toHaveURL(/\/vps\/host-1$/)
})

test('anonymous auth restore is quiet, deduplicated, and preserves the protected deep link', async ({ page }) => {
  const pageErrors: string[] = []
  let meRequests = 0
  page.on('pageerror', (error) => pageErrors.push(error.message))
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === '/api/v1/auth/me') meRequests += 1
  })
  await mockUnauthenticated(page)

  await page.goto('/users')
  await expect(page).toHaveURL(/\/login\?redirect=\/users$/)
  await expect(page.locator('input[type="email"]')).toBeVisible()
  await expect(page.locator('input[type="password"]')).toBeVisible()
  await expect.poll(() => meRequests).toBe(1)
  expect(pageErrors).toEqual([])
})

test('an invalid stale session cookie stays logged out without a retry loop', async ({ context, page }) => {
  const pageErrors: string[] = []
  let meRequests = 0
  page.on('pageerror', (error) => pageErrors.push(error.message))
  await context.addCookies([{
    name: 'guardian_session',
    value: 'stale-browser-test-session',
    domain: '127.0.0.1',
    path: '/',
    httpOnly: true,
    sameSite: 'Strict',
  }])
  await page.route('**/api/v1/**', async (route) => {
    if (new URL(route.request().url()).pathname === '/api/v1/auth/me') meRequests += 1
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ code: 'not_authenticated' }),
    })
  })

  await page.goto('/overview')
  await expect(page).toHaveURL(/\/login\?redirect=\/overview$/)
  await expect.poll(() => meRequests).toBe(1)
  expect(pageErrors).toEqual([])
})

test('login and logout return to a quiet logged-out state', async ({ page }) => {
  const pageErrors: string[] = []
  let authenticated = false
  let meRequests = 0
  page.on('pageerror', (error) => pageErrors.push(error.message))
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/auth/me') {
      meRequests += 1
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
          access_token: 'browser-login-session',
          csrf_token: 'browser-login-csrf',
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
    if (path === '/api/v1/overview') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(overview),
      })
      return
    }
    if (path === '/api/v1/stability') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(stability),
      })
      return
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
  })

  await page.goto('/login')
  await page.locator('input[type="email"]').fill('owner@example.test')
  await page.locator('input[type="password"]').fill('browser-only-password')
  await page.locator('button[type="submit"]').click()
  await expect(page).toHaveURL(/\/overview$/)
  await expect(page.getByRole('heading', { name: 'Operations Overview' })).toBeVisible()

  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login$/)
  await page.goto('/overview')
  await expect(page).toHaveURL(/\/login\?redirect=\/overview$/)
  expect(meRequests).toBeGreaterThanOrEqual(2)
  expect(pageErrors).toEqual([])
})

test('VPS list alias is usable on a mobile viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockController(page)
  await page.goto('/vps')
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()
  await expect(page.getByText('edge-hk', { exact: true })).toBeVisible()
  await expectNoHorizontalOverflow(page)
})

test('tablet drawer and wide desktop remain usable', async ({ page }) => {
  await page.setViewportSize({ width: 768, height: 1024 })
  await mockController(page)
  await page.goto('/overview')
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible()
  await page.getByRole('button', { name: 'Open navigation' }).click()
  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible()
  await expectNoHorizontalOverflow(page)

  await page.setViewportSize({ width: 1920, height: 1080 })
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Operations Overview' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
})

test('mobile Chinese alerts remain readable without overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockController(page, { locale: 'zh-CN', theme: 'light' })
  await page.goto('/alerts')
  await expect(page.getByRole('heading', { name: '告警' })).toBeVisible()
  await expect(page.getByText('HTTP status 503')).toBeVisible()
  await expect(page.getByRole('button', { name: '确认' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
})
