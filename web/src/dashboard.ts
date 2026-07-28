import { reactive } from 'vue'

import { request } from './api'
import type { User } from './types'

export type DashboardTone = 'healthy' | 'warning' | 'critical' | 'info' | 'neutral'

export interface DashboardBootstrap {
  generated_at: string
  user: Pick<User, 'id' | 'email' | 'role'>
  environment: {
    stage: string
    version: string
    production_deployed: boolean
    production_status: string
    gate_decision: string
    deployed_at: string | null
  }
  global_health: {
    status: 'healthy' | 'warning' | 'critical'
    reason: string
    critical: number
    warning: number
    updated_at: string
  }
  agents: {
    total: number
    online: number
    offline: number
    updated_at: string
  }
  alerts: {
    active: number
    critical: number
    warning: number
    info: number
    updated_at: string
  }
  backup: {
    status: string
    scope: 'offsite' | 'same_host'
    verified: boolean
    verified_at: string | null
    created_at: string | null
    check_status: string
    restore_status: string
    rpo_seconds: number | null
    rto_seconds: number | null
  }
  production_gate: {
    status: string
    decision: string
    production_deployed: boolean
    blockers: string[]
  }
  attention: Array<{
    id: string
    kind: string
    severity: DashboardTone
    severity_level: number
    title: string
    fault_type: string
    impact: { hosts: string[]; services: string[] }
    owner: string | null
    status: string
    occurred_at: string
    updated_at: string
    next_action: string | null
    href: string
  }>
  sections: Record<string, { status: string }>
}

export interface DashboardTopology {
  generated_at: string
  nodes: Array<{
    id: string
    label: string
    kind: 'control' | 'gateway' | 'database' | 'web' | 'agent'
    status: 'healthy' | 'degraded' | 'offline' | 'unknown'
  }>
}

export interface DashboardSecurity {
  generated_at: string
  controls: {
    uncovered_critical: number | null
    uncovered_high: number | null
    mtls: string
    crl: string
    certificate_rotation: string
    last_scan_at: string | null
    login_rate_limit: string
    totp: string
    rbac: string
    audit: string
  }
}

let loadPromise: Promise<void> | null = null

export const dashboard = reactive({
  data: null as DashboardBootstrap | null,
  loading: false,
  error: null as Error | null,
  async load(force = false): Promise<void> {
    if (this.data && !force) return
    if (loadPromise && !force) return loadPromise
    this.loading = true
    this.error = null
    loadPromise = (async () => {
      try {
        this.data = await request<DashboardBootstrap>('/api/v1/dashboard/bootstrap', {
          dedupe: true,
        })
      } catch (error) {
        this.error = error instanceof Error ? error : new Error(String(error))
        throw error
      } finally {
        this.loading = false
        loadPromise = null
      }
    })()
    return loadPromise
  },
  clear(): void {
    this.data = null
    this.error = null
    loadPromise = null
  },
})
