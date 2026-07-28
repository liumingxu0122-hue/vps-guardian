import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

function storage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => {
      values.delete(key)
    },
    setItem: (key, value) => {
      values.set(key, value)
    },
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('API request lifecycle', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.stubGlobal('sessionStorage', storage())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('treats an anonymous auth/me 401 as a normal restored logged-out session', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(401, { detail: { code: 'not_authenticated' } }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const { session } = await import('./session')

    await expect(session.restore()).resolves.toBeUndefined()
    await expect(session.restore()).resolves.toBeUndefined()

    expect(session.ready).toBe(true)
    expect(session.user).toBeNull()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('deduplicates a rejected GET without creating an unhandled derived promise', async () => {
    let release: ((response: Response) => void) | undefined
    const fetchMock = vi.fn().mockImplementation(
      () => new Promise<Response>((resolve) => {
        release = resolve
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const { request } = await import('./api')

    const first = request('/api/v1/auth/me')
    const second = request('/api/v1/auth/me')
    release?.(jsonResponse(401, { detail: { code: 'not_authenticated' } }))

    await expect(first).rejects.toMatchObject({ status: 401 })
    await expect(second).rejects.toMatchObject({ status: 401 })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('does not downgrade other client or server failures to logged-out state', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(503, { detail: { code: 'controller_unavailable' } }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const { session } = await import('./session')

    await expect(session.restore()).rejects.toMatchObject({
      status: 503,
      code: 'controller_unavailable',
    })
    expect(session.ready).toBe(true)
    expect(session.user).toBeNull()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('uses the browser-session login endpoint without persisting a bearer token', async () => {
    const sessionStorageSet = vi.fn()
    vi.stubGlobal('sessionStorage', {
      ...storage(),
      setItem: sessionStorageSet,
    })
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(200, {
        identity_setup_required: false,
        recovery_codes_remaining: null,
        remember_me: true,
        idle_expires_at: '2026-08-04T00:00:00Z',
        absolute_expires_at: '2026-08-27T00:00:00Z',
      }))
      .mockResolvedValueOnce(jsonResponse(200, {
        id: 'user-1',
        email: 'owner@example.test',
        role: 'owner',
      }))
    vi.stubGlobal('fetch', fetchMock)
    const { session } = await import('./session')

    await session.login('owner@example.test', 'a-long-browser-password', '', '', true)

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/auth/browser/login')
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toMatchObject({
      remember_me: true,
    })
    expect(sessionStorageSet).not.toHaveBeenCalled()
  })

  it('binds a mutation to the readable CSRF cookie without adding Authorization', async () => {
    vi.stubGlobal('document', { cookie: 'guardian_locale=zh-CN; guardian_csrf=bound-csrf' })
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    const { request } = await import('./api')

    await request('/api/v1/auth/activity', { method: 'POST' })

    const options = fetchMock.mock.calls[0]?.[1] as RequestInit
    const headers = options.headers as Headers
    expect(headers.get('X-CSRF-Token')).toBe('bound-csrf')
    expect(headers.has('Authorization')).toBe(false)
    expect(options.credentials).toBe('include')
  })
})
