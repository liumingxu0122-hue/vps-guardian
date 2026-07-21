import { expect, test, type Page } from '@playwright/test'

import type { Overview } from '../src/types'

const user = { id: 'user-1', email: 'owner@example.test', role: 'owner', totp_enabled: true }
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
  },
  global_health: 'degraded',
  hosts: { total: 2, healthy: 1, degraded: 1, offline: 0, unknown: 0 },
  incidents: { open: 2, critical: 1 },
  pending_approvals: 1,
  verified_recovery_points: 1,
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
      status: 'healthy',
      last_heartbeat_at: '2026-07-21T07:59:45Z',
      agent_serial: '1008',
      certificate_status: 'valid',
      offline_queue: 0,
      failed_tasks: 0,
      queued_tasks: 0,
      resources: { cpu_percent: 31.2, cpu_source: 'cpu_time', memory_percent: 48.1, disk_percent: 68.4, network_bytes_per_second: 34_200, collected_at: '2026-07-21T07:59:45Z' },
    },
    {
      id: 'host-2',
      name: 'staging-agent',
      location: 'Singapore',
      status: 'degraded',
      last_heartbeat_at: '2026-07-21T07:58:20Z',
      agent_serial: '1012',
      certificate_status: 'expiring',
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

interface MockOptions {
  payload?: Overview
  overviewStatus?: number
  delayMs?: number
  theme?: 'light' | 'dark'
}

async function mockController(page: Page, options: MockOptions = {}): Promise<void> {
  await page.addInitScript(({ theme }) => {
    sessionStorage.setItem('guardian_token', 'browser-test-session')
    localStorage.setItem('guardian_theme', theme)
  }, { theme: options.theme ?? 'dark' })
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
        body: JSON.stringify(options.overviewStatus ? { detail: 'Controller 暂时不可用' } : options.payload ?? overview),
      })
      return
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
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
  await expect(page.getByText('Production 未部署', { exact: true })).toBeVisible()
  await expect(page.getByText('a492e73f5698', { exact: true }).first()).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: 'test-results/overview-desktop-dark.png', fullPage: true })
})

test('mobile overview renders API data in light mode', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockController(page, { theme: 'light' })
  await page.goto('/overview')
  await expect(page.getByText('允许受控生产规划')).toBeVisible()
  await expect(page.locator('.ops-host-name strong').filter({ hasText: 'staging-controller' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: 'test-results/overview-mobile-light.png', fullPage: true })
})

test('theme control switches between light and dark', async ({ page }) => {
  await mockController(page, { theme: 'dark' })
  await page.goto('/overview')
  await page.getByRole('button', { name: '切换到亮色模式' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await expect(page.getByRole('button', { name: '切换到暗色模式' })).toBeVisible()
})

test('loading and API failure states are explicit', async ({ page }) => {
  await mockController(page, { delayMs: 700 })
  const overviewResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/v1/overview',
  )
  await page.goto('/overview')
  await expect(page.getByLabel('正在加载运营总览')).toBeVisible()
  await overviewResponse
  await expect(page.getByRole('heading', { name: 'Operations Overview' })).toBeVisible()

  await page.unroute('**/api/v1/**')
  await mockController(page, { overviewStatus: 503 })
  await page.reload()
  await expect(page.getByRole('alert')).toContainText('Controller API 不可用')
})

test('empty and restricted states do not expose actions', async ({ page }) => {
  const restricted: Overview = {
    ...overview,
    hosts: { total: 0, healthy: 0, degraded: 0, offline: 0, unknown: 0 },
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
  await expect(page.getByText('当前范围没有资源样本')).toBeVisible()
  await expect(page.getByText('尚未登记 VPS')).toBeVisible()
  await expect(page.getByText('详细恢复操作需要 Operator 权限')).toBeVisible()
  await expect(page.getByText('安全详情需要 Admin 权限')).toBeVisible()
  await expect(page.getByRole('button', { name: /删除|forget|prune|恢复|重启|轮换/i })).toHaveCount(0)
})
