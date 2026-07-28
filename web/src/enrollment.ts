const terminalEnrollmentStates = new Set(['completed', 'failed', 'expired', 'revoked'])

export function isTerminalEnrollment(status: string | null | undefined): boolean {
  return Boolean(status && terminalEnrollmentStates.has(status))
}

export function enrollmentSecondsRemaining(expiresAt: string, now: number): number {
  const expiry = Date.parse(expiresAt)
  if (!Number.isFinite(expiry)) return 0
  return Math.max(0, Math.ceil((expiry - now) / 1_000))
}
