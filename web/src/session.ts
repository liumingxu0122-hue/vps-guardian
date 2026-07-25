import { reactive } from 'vue'

import { ApiError, jsonBody, request } from './api'
import type { User } from './types'

interface LoginResponse {
  access_token: string
  csrf_token: string
  identity_setup_required: boolean
  recovery_codes_remaining: number | null
}

let restorePromise: Promise<void> | null = null

export const session = reactive({
  user: null as User | null,
  recoveryCodesRemaining: null as number | null,
  ready: false,
  async restore(): Promise<void> {
    if (this.ready) return
    if (restorePromise) return restorePromise
    restorePromise = (async () => {
      try {
        this.user = await request<User>('/api/v1/auth/me')
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 401) throw error
        sessionStorage.removeItem('guardian_token')
        sessionStorage.removeItem('guardian_csrf')
        this.user = null
      } finally {
        this.ready = true
      }
    })()
    return restorePromise
  },
  async login(email: string, password: string, totpCode: string, recoveryCode = ''): Promise<void> {
    const payload = await request<LoginResponse>('/api/v1/auth/login', {
      method: 'POST',
      ...jsonBody({
        email,
        password,
        totp_code: totpCode || null,
        recovery_code: recoveryCode || null,
      }),
    })
    sessionStorage.setItem('guardian_token', payload.access_token)
    sessionStorage.setItem('guardian_csrf', payload.csrf_token)
    this.user = await request<User>('/api/v1/auth/me')
    this.recoveryCodesRemaining = payload.recovery_codes_remaining
    this.ready = true
  },
  async replaceCredentials(payload: LoginResponse): Promise<void> {
    sessionStorage.setItem('guardian_token', payload.access_token)
    sessionStorage.setItem('guardian_csrf', payload.csrf_token)
    this.user = await request<User>('/api/v1/auth/me')
  },
  async refreshUser(): Promise<void> {
    this.user = await request<User>('/api/v1/auth/me')
  },
  async logout(): Promise<void> {
    try {
      await request<void>('/api/v1/auth/logout', { method: 'POST' })
    } finally {
      sessionStorage.removeItem('guardian_token')
      sessionStorage.removeItem('guardian_csrf')
      this.user = null
      this.recoveryCodesRemaining = null
    }
  },
})
