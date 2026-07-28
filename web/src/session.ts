import { reactive } from 'vue'

import {
  ApiError,
  jsonBody,
  request,
  resetAuthFailure,
  setAuthFailureHandler,
} from './api'
import type { User } from './types'

interface LoginResponse {
  identity_setup_required: boolean
  recovery_codes_remaining: number | null
  remember_me: boolean
  idle_expires_at: string
  absolute_expires_at: string
}

let restorePromise: Promise<void> | null = null
let activityTimer = 0
let lastActivitySentAt = 0
const ACTIVITY_SEND_INTERVAL_MS = 300_000

export type AuthState =
  | 'unknown'
  | 'restoring'
  | 'authenticated'
  | 'unauthenticated'
  | 'temporarily_unavailable'
  | 'forbidden'

export const session = reactive({
  user: null as User | null,
  recoveryCodesRemaining: null as number | null,
  ready: false,
  error: null as Error | null,
  state: 'unknown' as AuthState,
  invalidReason: null as string | null,
  async restore(): Promise<void> {
    if (this.ready) return
    if (restorePromise) return restorePromise
    restorePromise = (async () => {
      this.state = 'restoring'
      try {
        this.user = await request<User>('/api/v1/auth/me')
        this.error = null
        this.state = 'authenticated'
        this.invalidReason = null
        resetAuthFailure()
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          this.error = null
          this.state = 'unauthenticated'
          this.invalidReason = error.code
        } else if (error instanceof ApiError && error.status === 403) {
          this.error = error
          this.state = 'forbidden'
          throw error
        } else if (error instanceof DOMException && error.name === 'AbortError') {
          throw error
        } else {
          this.error = error instanceof Error ? error : new Error(String(error))
          this.user = null
          this.state = 'temporarily_unavailable'
          throw error
        }
        this.user = null
      } finally {
        this.ready = true
        restorePromise = null
      }
    })()
    return restorePromise
  },
  async retryRestore(): Promise<void> {
    this.ready = false
    this.error = null
    await this.restore()
  },
  async login(
    email: string,
    password: string,
    totpCode: string,
    recoveryCode = '',
    rememberMe = false,
  ): Promise<void> {
    const payload = await request<LoginResponse>('/api/v1/auth/browser/login', {
      method: 'POST',
      ...jsonBody({
        email,
        password,
        totp_code: totpCode || null,
        recovery_code: recoveryCode || null,
        remember_me: rememberMe,
      }),
    })
    this.user = await request<User>('/api/v1/auth/me')
    this.error = null
    this.recoveryCodesRemaining = payload.recovery_codes_remaining
    this.ready = true
    this.state = 'authenticated'
    this.invalidReason = null
    resetAuthFailure()
  },
  async replaceCredentials(_payload: unknown): Promise<void> {
    this.user = await request<User>('/api/v1/auth/me')
    this.state = 'authenticated'
  },
  async refreshUser(): Promise<void> {
    this.user = await request<User>('/api/v1/auth/me')
  },
  async logout(): Promise<void> {
    try {
      await request<void>('/api/v1/auth/logout', { method: 'POST' })
    } finally {
      this.user = null
      this.recoveryCodesRemaining = null
      this.error = null
      this.state = 'unauthenticated'
    }
  },
  async recordActivity(activityType: 'pointer' | 'keyboard'): Promise<void> {
    if (!this.user || document.visibilityState !== 'visible') return
    await request('/api/v1/auth/activity', {
      method: 'POST',
      headers: { 'X-Guardian-Activity-Type': activityType },
    })
  },
})

setAuthFailureHandler((error) => {
  session.user = null
  session.error = null
  session.state = 'unauthenticated'
  session.invalidReason = error.code
  session.ready = true
})

export function installActivityTracking(): () => void {
  const record = (event: Event): void => {
    if (!session.user || document.visibilityState !== 'visible') return
    if (Date.now() - lastActivitySentAt < ACTIVITY_SEND_INTERVAL_MS) return
    window.clearTimeout(activityTimer)
    activityTimer = window.setTimeout(() => {
      const type = event.type === 'keydown' ? 'keyboard' : 'pointer'
      lastActivitySentAt = Date.now()
      void session.recordActivity(type).catch(() => undefined)
    }, 250)
  }
  window.addEventListener('pointerdown', record, { passive: true })
  window.addEventListener('keydown', record)
  return () => {
    window.clearTimeout(activityTimer)
    window.removeEventListener('pointerdown', record)
    window.removeEventListener('keydown', record)
  }
}
