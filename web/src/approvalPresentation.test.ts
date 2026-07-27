import { describe, expect, it } from 'vitest'

import { filterApprovalSummaries, shouldLoadApprovalEvidence } from './approvalPresentation'
import type { ApprovalSummary } from './types'

const approvals: ApprovalSummary[] = [
  {
    id: 'one',
    incident_id: 'incident-one',
    action_name: 'service_restart',
    status: 'pending',
    risk_level: 2,
    target: { host: 'edge-hk', service: 'gateway', scope: 'staging' },
    requester: { label: 'operator', role: 'operator' },
    requested_at: '2026-07-25T07:40:00Z',
    expires_at: '2026-07-25T09:40:00Z',
    progress_label: 'awaiting_decision',
    execution_status: null,
  },
  {
    id: 'two',
    incident_id: 'incident-two',
    action_name: 'restricted_cleanup',
    status: 'executed',
    risk_level: 3,
    target: { host: 'worker-hk', service: 'filesystem', scope: 'staging' },
    requester: { label: 'owner', role: 'owner' },
    requested_at: '2026-07-24T07:40:00Z',
    expires_at: '2026-07-24T09:40:00Z',
    progress_label: 'completed',
    execution_status: 'completed',
  },
]

describe('approval presentation', () => {
  it('combines query, status, and risk filters without matching hidden identifiers', () => {
    expect(filterApprovalSummaries(approvals, 'worker', 'executed', 3).map((item) => item.id))
      .toEqual(['two'])
    expect(filterApprovalSummaries(approvals, 'incident-one', 'all', 'all')).toEqual([])
  })

  it('loads restricted evidence only after an authorized explicit expansion', () => {
    expect(shouldLoadApprovalEvidence(false, false, true)).toBe(false)
    expect(shouldLoadApprovalEvidence(true, false, false)).toBe(false)
    expect(shouldLoadApprovalEvidence(true, true, true)).toBe(false)
    expect(shouldLoadApprovalEvidence(true, false, true)).toBe(true)
  })
})
