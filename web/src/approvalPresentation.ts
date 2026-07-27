import type { ApprovalStatus, ApprovalSummary } from './types'

export function filterApprovalSummaries(
  approvals: ApprovalSummary[],
  query: string,
  status: ApprovalStatus | 'all',
  risk: number | 'all',
): ApprovalSummary[] {
  const needle = query.trim().toLocaleLowerCase()
  return approvals.filter((item) => {
    if (status !== 'all' && item.status !== status) return false
    if (risk !== 'all' && item.risk_level !== risk) return false
    if (!needle) return true
    return [
      item.action_name,
      item.target.host,
      item.target.service,
      item.requester?.label,
    ].some((value) => value?.toLocaleLowerCase().includes(needle))
  })
}

export function shouldLoadApprovalEvidence(
  isOpen: boolean,
  alreadyLoaded: boolean,
  canReadEvidence: boolean,
): boolean {
  return isOpen && !alreadyLoaded && canReadEvidence
}
