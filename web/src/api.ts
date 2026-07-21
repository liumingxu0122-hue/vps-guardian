const API_BASE = import.meta.env.VITE_API_BASE_URL ?? ''

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message)
  }
}

interface RequestOptions extends RequestInit {
  body?: string
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers)
  const token = sessionStorage.getItem('guardian_token')
  const csrf = sessionStorage.getItem('guardian_csrf')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (csrf && !['GET', 'HEAD'].includes(options.method ?? 'GET')) {
    headers.set('X-CSRF-Token', csrf)
  }
  if (options.body) headers.set('Content-Type', 'application/json')
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: 'include',
  })
  if (!response.ok) {
    let message = `请求失败 (${response.status})`
    try {
      const payload = (await response.json()) as { detail?: string }
      if (payload.detail) message = payload.detail
    } catch {
      // The status still carries enough information when the body is not JSON.
    }
    throw new ApiError(response.status, message)
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

export function jsonBody(value: unknown): { body: string } {
  return { body: JSON.stringify(value) }
}
