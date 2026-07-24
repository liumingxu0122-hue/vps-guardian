import { expect, test } from '@playwright/test'

const explicitlyEnabled = process.env.RUN_PROTECTED_PANEL_MANUAL === '1'
const baseURL = process.env.PROTECTED_PANEL_BASE_URL
const email = process.env.PANEL_EMAIL
const password = process.env.PANEL_PASSWORD

test.skip(
  !explicitlyEnabled || !baseURL || !email || !password,
  'real protected-panel validation is opt-in and never runs in automated tests',
)

test('protected panel keeps authentication and read boundaries', async ({ page }) => {
  if (!baseURL || !email || !password) throw new Error('manual test configuration is incomplete')

  await page.goto(new URL('/vps', baseURL).toString())
  await expect(page).toHaveURL(/\/login\?redirect=\/vps$/)
  expect(
    await page.evaluate(() => fetch('/api/v1/hosts').then((response) => response.status)),
  ).toBe(401)

  await page.locator('input[type="email"]').fill(email)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.locator('button[type="submit"]').click()
  await expect(page).toHaveURL(/\/vps$/)
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()

  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login$/)
  expect(
    await page.evaluate(() => fetch('/api/v1/hosts').then((response) => response.status)),
  ).toBe(401)
})
