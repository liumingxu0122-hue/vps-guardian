import { expect, test, type Page } from '@playwright/test'

const user = {
  id: 'owner-1',
  email: 'owner@example.test',
  role: 'owner',
  totp_enabled: true,
  is_active: true,
  scopes: [],
  last_login_at: '2026-07-29T00:00:00Z',
  password_changed_at: '2026-07-20T00:00:00Z',
  totp_enabled_at: '2026-07-20T00:00:00Z',
  disabled_at: null,
  must_change_password: false,
  identity_setup_required: false,
  created_by: null,
  disabled_by: null,
  created_at: '2026-07-01T00:00:00Z',
}

const host = {
  id: 'host-maintenance-1',
  name: 'edge-maintenance',
  primary_address: '192.0.2.44',
  os_name: 'Ubuntu 24.04',
  region: 'Hong Kong',
  group: 'edge',
  provider: 'Example',
  purpose: 'Staging',
  display_tags: ['staging'],
  health: 'healthy',
  data_state: 'normal',
  enabled: true,
  management: 'guardian',
  agent_state: 'online',
  agent_version: '0.4.0',
  last_heartbeat_at: '2026-07-29T00:00:00Z',
  last_seen_at: '2026-07-29T00:00:00Z',
  enrolled_at: '2026-07-01T00:00:00Z',
  data_reason: 'available',
  resource_summary: { cpu_percent: 10 },
  technical_evidence_available: true,
}

async function mockApi(page: Page): Promise<string> {
  const secretCommand = 'one-time-maintenance-secret-command'
  await page.context().addCookies([{
    name: 'guardian_locale',
    value: 'en-US',
    url: 'http://127.0.0.1:4173',
    sameSite: 'Lax',
  }])
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === '/api/v1/auth/me') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(user) })
      return
    }
    if (path === '/api/v1/hosts/presentation') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([host]) })
      return
    }
    if (path === '/api/v1/dashboard/bootstrap') {
      const now = new Date().toISOString()
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          generated_at: now,
          user: { id: user.id, email: user.email, role: user.role },
          environment: {
            stage: 'staging', version: '0.4.0-test', production_deployed: false,
            production_status: 'not_deployed', gate_decision: 'production_no_go', deployed_at: null,
          },
          global_health: { status: 'healthy', reason: 'test', critical: 0, warning: 0, updated_at: now },
          agents: { total: 1, online: 1, offline: 0, updated_at: now },
          alerts: { active: 0, critical: 0, warning: 0, info: 0, updated_at: now },
          backup: {
            status: 'healthy', scope: 'test', verified: true, verified_at: now,
            created_at: now, check_status: 'passed', restore_status: 'passed',
            rpo_seconds: 0, rto_seconds: 0,
          },
          production_gate: {
            status: 'blocked', decision: 'production_no_go',
            production_deployed: false, blockers: ['test'],
          },
          attention: [],
          sections: {
            health: { status: 'ok' }, agents: { status: 'ok' }, alerts: { status: 'ok' },
            backup: { status: 'ok' }, attention: { status: 'ok' },
          },
        }),
      })
      return
    }
    if (path.endsWith('/maintenance-sessions') && request.method() === 'POST') {
      expect(request.postDataJSON()).toMatchObject({ kind: 'repair', purge_local_state: false })
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          id: 'maintenance-session-1',
          host_id: host.id,
          kind: 'repair',
          expires_at: new Date(Date.now() + 600_000).toISOString(),
          command: secretCommand,
          status: 'waiting',
        }),
      })
      return
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
  })
  return secretCommand
}

for (const scenario of [
  { name: 'desktop dark', width: 1440, height: 900, theme: 'dark' },
  { name: 'mobile light', width: 390, height: 844, theme: 'light' },
] as const) {
  test(`maintenance disclosure and high-risk controls work on ${scenario.name}`, async ({ page }) => {
    await page.setViewportSize({ width: scenario.width, height: scenario.height })
    await page.addInitScript((theme) => localStorage.setItem('guardian_theme', theme), scenario.theme)
    const command = await mockApi(page)
    const errors: string[] = []
    page.on('pageerror', (error) => errors.push(error.message))
    await page.goto('/hosts')
    await page.getByText('edge-maintenance', { exact: true }).click()
    await page.getByRole('button', { name: 'Repair' }).click()
    const repair = page.getByRole('dialog')
    await repair.getByRole('button', { name: 'Generate one-time command' }).click()
    await expect(repair.getByLabel('One-time maintenance command')).toHaveValue(command)
    await repair.getByRole('button', { name: 'Done' }).click()
    await expect(page.getByText(command)).toHaveCount(0)

    await page.getByRole('button', { name: 'Decommission' }).click()
    const decommission = page.getByRole('dialog')
    await expect(decommission.getByText('Decommission stops Agent tasks', { exact: false })).toBeVisible()
    await expect(decommission.getByLabel('Approved request ID')).toBeVisible()
    await expect(decommission.getByLabel('Type the exact host name')).toBeVisible()
    await expect(page.locator('html')).toHaveAttribute('data-theme', scenario.theme)
    expect(errors).toEqual([])
  })
}
