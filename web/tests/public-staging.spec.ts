import { expect, test } from '@playwright/test'

const publicHost = {
  name: 'public-staging-node',
  location: 'Hong Kong',
  status: 'healthy',
  data_state: 'normal',
  last_seen_at: '2026-07-25T04:00:00Z',
  resources: {
    cpu_percent: 12.5,
    memory_percent: 34.5,
    disk_percent: 56.5,
    collected_at: '2026-07-25T04:00:00Z',
  },
}

test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/auth/me', (route) =>
    route.fulfill({ status: 401, contentType: 'application/json', body: '{}' }),
  )
  await page.route('**/api/v1/public/session', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ mode: 'anonymous_read_only', deployment_stage: 'staging' }),
    }),
  )
  await page.route('**/api/v1/public/overview', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        generated_at: '2026-07-25T04:00:00Z',
        global_health: 'healthy',
        hosts: { total: 1, healthy: 1, degraded: 0, offline: 0, unknown: 0 },
        host_rows: [publicHost],
      }),
    }),
  )
  await page.route('**/api/v1/public/hosts', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([publicHost]),
    }),
  )
})

test('public staging exposes only the reduced navigation and projections', async ({ page }) => {
  await page.goto('/overview')

  await expect(page.getByRole('heading', { name: 'Public staging overview' })).toBeVisible()
  await expect(page.getByText('Public staging · read-only')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Overview' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Hosts' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Audit log' })).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'Backup & Restore' })).toHaveCount(0)
  await expect(page.getByText('public-staging-node')).toBeVisible()

  await page.goto('/vps')
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()
  await expect(page.getByText('Internal details hidden')).toBeVisible()
})
