import { reactive } from 'vue'

import { ApiError, jsonBody, request } from './api'
import type { PublicSession, User } from './types'

interface LoginResponse {
  access_token: string
  csrf_token: string
}

let restorePromise: Promise<void> | null = null

export const session = reactive({
  user: null as User | null,
  publicReadOnly: false,
  ready: false,
  async restore(): Promise<void> {
    if (this.ready) return
    if (restorePromise) return restorePromise
    restorePromise = (async () => {
      try {
        this.user = await request<User>('/api/v1/auth/me')
        this.publicReadOnly = false
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 401) throw error
        this.user = null
        try {
          await request<PublicSession>('/api/v1/public/session')
          this.publicReadOnly = true
        } catch (publicError) {
          if (
            !(publicError instanceof ApiError) ||
            ![401, 403, 404].includes(publicError.status)
          ) {
            throw publicError
          }
          this.publicReadOnly = false
          if (publicError.status !== 401) {
            sessionStorage.removeItem('guardian_token')
            sessionStorage.removeItem('guardian_csrf')
          }
        }
      } finally {
        this.ready = true
        restorePromise = null
      }
    })()
    return restorePromise
  },
  async login(email: string, password: string, totpCode: string): Promise<void> {
    const payload = await request<LoginResponse>('/api/v1/auth/login', {
      method: 'POST',
      ...jsonBody({ email, password, totp_code: totpCode || null }),
    })
    sessionStorage.setItem('guardian_token', payload.access_token)
    sessionStorage.setItem('guardian_csrf', payload.csrf_token)
    this.user = await request<User>('/api/v1/auth/me')
    this.publicReadOnly = false
    this.ready = true
  },
  async logout(): Promise<void> {
    try {
      await request<void>('/api/v1/auth/logout', { method: 'POST' })
    } finally {
      sessionStorage.removeItem('guardian_token')
      sessionStorage.removeItem('guardian_csrf')
      this.user = null
      this.publicReadOnly = false
    }
  },
})
