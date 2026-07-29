import { describe, expect, it } from 'vitest'

import {
  canIssueMaintenance,
  canViewMaintenance,
  destroyMaintenanceDisclosure,
} from './maintenance'
import type { AgentMaintenanceToken } from './types'

describe('Agent maintenance disclosure and RBAC', () => {
  it('permits Operators only for repair', () => {
    expect(canIssueMaintenance('viewer', 'repair')).toBe(false)
    expect(canIssueMaintenance('operator', 'repair')).toBe(true)
    expect(canIssueMaintenance('operator', 'reinstall')).toBe(false)
    expect(canIssueMaintenance('admin', 'rotate_identity')).toBe(true)
    expect(canIssueMaintenance('owner', 'decommission')).toBe(true)
    expect(canViewMaintenance('viewer')).toBe(false)
    expect(canViewMaintenance('auditor')).toBe(true)
  })

  it('destroys command plaintext when the dialog closes', () => {
    const token: AgentMaintenanceToken = {
      id: 'session',
      host_id: 'host',
      kind: 'repair',
      expires_at: new Date().toISOString(),
      command: 'sensitive one-time command',
      status: 'waiting',
    }
    expect(destroyMaintenanceDisclosure(token)).toBeNull()
    expect(token.command).toBe('')
  })
})
