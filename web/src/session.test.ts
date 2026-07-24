import { beforeEach, describe, expect, it, vi } from 'vitest'

import { session } from './session'

class MemoryStorage implements Storage {
  private values = new Map<string, string>()
  get length(): number { return this.values.size }
  clear(): void { this.values.clear() }
  getItem(key: string): string | null { return this.values.get(key) ?? null }
  key(index: number): string | null { return [...this.values.keys()][index] ?? null }
  removeItem(key: string): void { this.values.delete(key) }
  setItem(key: string, value: string): void { this.values.set(key, value) }
}

function jsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('session restoration boundaries', () => {
  beforeEach(() => {
    vi.stubGlobal('sessionStorage', new MemoryStorage())
    session.user = null
    session.publicReadOnly = false
    session.ready = false
  })

  it('enters public staging only after the authenticated session is absent', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(401, { detail: 'authentication required' }))
      .mockResolvedValueOnce(
        jsonResponse(200, {
          mode: 'anonymous_read_only',
          deployment_stage: 'staging',
        }),
      )
    vi.stubGlobal('fetch', fetchMock)

    await session.restore()

    expect(session.publicReadOnly).toBe(true)
    expect(session.user).toBeNull()
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual([
      '/api/v1/auth/me',
      '/api/v1/public/session',
    ])
  })

  it('does not downgrade an invalid bearer credential to public access', async () => {
    sessionStorage.setItem('guardian_token', 'invalid-explicit-token')
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(401, { detail: 'invalid token' }))
      .mockResolvedValueOnce(jsonResponse(401, { detail: 'invalid token' }))
    vi.stubGlobal('fetch', fetchMock)

    await session.restore()

    expect(session.publicReadOnly).toBe(false)
    expect(sessionStorage.getItem('guardian_token')).toBe('invalid-explicit-token')
    const publicHeaders = new Headers(fetchMock.mock.calls[1]?.[1]?.headers)
    expect(publicHeaders.get('Authorization')).toBe('Bearer invalid-explicit-token')
  })

  it('keeps protected panels on the login flow when public mode is unavailable', async () => {
    sessionStorage.setItem('guardian_token', 'stale-token')
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(401, { detail: 'invalid token' }))
      .mockResolvedValueOnce(jsonResponse(404, { detail: 'not found' }))
    vi.stubGlobal('fetch', fetchMock)

    await session.restore()

    expect(session.publicReadOnly).toBe(false)
    expect(sessionStorage.getItem('guardian_token')).toBeNull()
  })

  it('treats a forbidden public probe as a protected panel, not public access', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(401, { detail: 'authentication required' }))
      .mockResolvedValueOnce(jsonResponse(403, { detail: 'forbidden' }))
    vi.stubGlobal('fetch', fetchMock)

    await session.restore()

    expect(session.publicReadOnly).toBe(false)
    expect(session.user).toBeNull()
  })
})
