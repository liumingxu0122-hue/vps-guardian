import type { AgentMaintenanceToken } from './types'

export function canIssueMaintenance(
  role: string | undefined,
  kind: AgentMaintenanceToken['kind'],
): boolean {
  if (kind === 'repair') return ['operator', 'admin', 'owner'].includes(role ?? '')
  return ['admin', 'owner'].includes(role ?? '')
}
export function canViewMaintenance(role: string | undefined): boolean {
  return ['auditor', 'operator', 'admin', 'owner'].includes(role ?? '')
}
export function destroyMaintenanceDisclosure(
  disclosure: AgentMaintenanceToken | null,
): null {
  if (disclosure) disclosure.command = ''
  return null
}
