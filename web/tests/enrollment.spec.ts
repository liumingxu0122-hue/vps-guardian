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

async function mockEnrollmentApi(page: Page): Promise<{
  commands: string[]
  revocations: string[]
}> {
  let hostCreated = false
  let issueCount = 0
  let statusPolls = 0
  const commands: string[] = []
  const revocations: string[] = []
  const host = {
    id: '19ca9b96-a220-44ce-b37d-e27ca4a77701',
    name: 'edge-new',
    address: 'pending-enrollment',
    os_name: null,
    location: 'Hong Kong',
    notes: 'Staging edge',
    desired_os_family: 'debian',
    status: 'pending',
    data_state: 'pending_enrollment',
    enabled: true,
    group_name: 'edge',
    tags: [],
    labels: {},
    last_seen_at: null,
    enrolled_at: null,
    disabled_at: null,
  }
  const presentation = {
    id: host.id,
    name: host.name,
    primary_address: host.address,
    os_name: null,
    region: host.location,
    group: host.group_name,
    provider: null,
    purpose: null,
    display_tags: [],
    health: 'unknown',
    data_state: 'no_data',
    enabled: true,
    management: 'pending_enrollment',
    agent_state: 'not_installed',
    agent_version: null,
    last_heartbeat_at: null,
    last_seen_at: null,
    enrolled_at: null,
    data_reason: 'pending_enrollment',
    resource_summary: null,
    technical_evidence_available: false,
  }
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
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(hostCreated ? [presentation] : []),
      })
      return
    }
    if (path === '/api/v1/dashboard/bootstrap') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          generated_at: new Date().toISOString(),
          user: { id: user.id, email: user.email, role: user.role },
          environment: {
            stage: 'staging',
            version: '0.4.0-test',
            production_deployed: false,
            production_status: 'not_deployed',
            gate_decision: 'production_no_go',
            deployed_at: null,
          },
          global_health: {
            status: 'healthy',
            reason: 'test',
            critical: 0,
            warning: 0,
            updated_at: new Date().toISOString(),
          },
          agents: { total: 0, online: 0, offline: 0, updated_at: new Date().toISOString() },
          alerts: { active: 0, critical: 0, warning: 0, info: 0, updated_at: new Date().toISOString() },
          backup: {
            status: 'healthy',
            scope: 'test',
            verified: true,
            verified_at: new Date().toISOString(),
            created_at: new Date().toISOString(),
            check_status: 'passed',
            restore_status: 'passed',
            rpo_seconds: 0,
            rto_seconds: 0,
          },
          production_gate: {
            status: 'blocked',
            decision: 'production_no_go',
            production_deployed: false,
            blockers: ['test'],
          },
          attention: [],
          sections: {
            health: { status: 'ok' },
            agents: { status: 'ok' },
            alerts: { status: 'ok' },
            backup: { status: 'ok' },
            attention: { status: 'ok' },
          },
        }),
      })
      return
    }
    if (path === '/api/v1/hosts' && request.method() === 'POST') {
      const payload = request.postDataJSON()
      expect(payload.address).toBe('pending-enrollment')
      expect(payload.desired_os_family).toBe('debian')
      expect(payload.tags).toEqual(['staging', 'edge'])
      expect(payload.source_cidr).toBeUndefined()
      hostCreated = true
      await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(host) })
      return
    }
    if (path.endsWith('/enrollment-token') && request.method() === 'POST') {
      const payload = request.postDataJSON()
      expect(payload.expires_in_minutes).toBe(10)
      expect(payload.os_family).toBe('debian')
      expect(payload.source_cidr).toBe('203.0.113.10/32')
      issueCount += 1
      statusPolls = 0
      const secret = `test-enrollment-command-secret-${issueCount}-xxxxxxxx`
      const command = `umask 077; printf %s ${secret} >"$guardian_tmp/enrollment-token"`
      commands.push(command)
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          id: `enrollment-${issueCount}`,
          host_id: host.id,
          expires_at: new Date(Date.now() + 600_000).toISOString(),
          install_command: command,
          status: 'waiting',
        }),
      })
      return
    }
    if (path.endsWith('/enrollment-sessions/latest')) {
      statusPolls += 1
      const completed = statusPolls >= 2
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          id: `enrollment-${issueCount}`,
          host_id: host.id,
          status: completed ? 'completed' : 'installer_verified',
          sequence: completed ? 12 : 2,
          expires_at: new Date(Date.now() + 600_000).toISOString(),
          used_at: completed ? new Date().toISOString() : null,
          revoked_at: null,
          completed_at: completed ? new Date().toISOString() : null,
          source_cidr: '203.0.113.10/32',
          os_family: 'debian',
          error_code: null,
          error_step: null,
          error_summary: null,
          rolled_back: false,
          events: [{
            status: completed ? 'completed' : 'installer_verified',
            sequence: completed ? 12 : 2,
            occurred_at: new Date().toISOString(),
            error_code: null,
            error_summary: null,
            rolled_back: false,
          }],
        }),
      })
      return
    }
    if (path.includes('/enrollment-tokens/') && path.endsWith('/revoke')) {
      revocations.push(path)
      await route.fulfill({ status: 204 })
      return
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
  })
  return { commands, revocations }
}

test('add-server wizard creates one-time command, polls progress, and clears disclosure', async ({ page }) => {
  const state = await mockEnrollmentApi(page)
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.goto('/hosts')

  await page.getByRole('button', { name: 'Add host' }).click()
  const addDialog = page.getByRole('dialog')
  await addDialog.getByLabel('Name').fill('edge-new')
  await addDialog.getByLabel('Region').fill('Hong Kong')
  await addDialog.getByLabel('Group').fill('edge')
  await addDialog.getByLabel('Tags').fill('staging, edge')
  await addDialog.getByLabel('Operating-system family').selectOption('debian')
  await addDialog.getByLabel('Allowed source CIDR (optional)').fill('203.0.113.10/32')
  await addDialog.getByLabel('Notes').fill('Staging edge')
  await addDialog.getByRole('button', { name: 'Create and generate command' }).click()

  const enrollmentDialog = page.getByRole('dialog')
  await expect(enrollmentDialog.getByText('The command contains a short-lived credential.')).toBeVisible()
  await expect(enrollmentDialog.getByLabel('Verified-bundle install command')).toHaveValue(state.commands[0])
  await expect(enrollmentDialog.getByText('Enrollment completed').first()).toBeVisible({ timeout: 6_000 })
  await enrollmentDialog.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByText(state.commands[0])).toHaveCount(0)
  expect(errors).toEqual([])
})
