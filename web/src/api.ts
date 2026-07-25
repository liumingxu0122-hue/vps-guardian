const API_BASE = import.meta.env.VITE_API_BASE_URL ?? ''

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code)
  }
}

interface RequestOptions extends RequestInit {
  body?: string
  dedupe?: boolean
}

const inFlightGets = new Map<string, Promise<unknown>>()

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase()
  const shouldDedupe = method === 'GET' && options.dedupe !== false && !options.signal
  const requestKey = `${method}:${path}:${sessionStorage.getItem('guardian_token') ?? ''}`
  const existing = inFlightGets.get(requestKey)
  if (shouldDedupe && existing) return existing as Promise<T>

  const operation = performRequest<T>(path, options)
  if (!shouldDedupe) return operation

  const trackedOperation = operation.finally(() => inFlightGets.delete(requestKey))
  inFlightGets.set(requestKey, trackedOperation)
  return trackedOperation
}

async function performRequest<T>(path: string, options: RequestOptions): Promise<T> {
  const { dedupe: _dedupe, ...fetchOptions } = options
  const headers = new Headers(options.headers)
  const token = sessionStorage.getItem('guardian_token')
  const csrf = sessionStorage.getItem('guardian_csrf')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (csrf && !['GET', 'HEAD'].includes(options.method ?? 'GET')) {
    headers.set('X-CSRF-Token', csrf)
  }
  if (options.body) headers.set('Content-Type', 'application/json')
  const response = await fetch(`${API_BASE}${path}`, {
    ...fetchOptions,
    headers,
    credentials: 'include',
  })
  if (!response.ok) {
    let code = `http_${response.status}`
    try {
      const payload = (await response.json()) as { code?: string; detail?: { code?: string } | string }
      if (payload.code) code = payload.code
      else if (typeof payload.detail === 'object' && payload.detail?.code) code = payload.detail.code
    } catch {
      // The status still carries enough information when the body is not JSON.
    }
    throw new ApiError(response.status, code)
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

export function jsonBody(value: unknown): { body: string } {
  return { body: JSON.stringify(value) }
}
