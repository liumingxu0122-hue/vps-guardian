import { describe, expect, it } from 'vitest'

import { enrollmentSecondsRemaining, isTerminalEnrollment } from './enrollment'

describe('Agent enrollment presentation', () => {
  it('stops polling only for terminal server states', () => {
    expect(isTerminalEnrollment('waiting')).toBe(false)
    expect(isTerminalEnrollment('service_started')).toBe(false)
    expect(isTerminalEnrollment('completed')).toBe(true)
    expect(isTerminalEnrollment('failed')).toBe(true)
    expect(isTerminalEnrollment('expired')).toBe(true)
    expect(isTerminalEnrollment('revoked')).toBe(true)
  })

  it('counts down without exposing negative or invalid time', () => {
    const now = Date.parse('2026-07-29T00:00:00Z')
    expect(enrollmentSecondsRemaining('2026-07-29T00:00:10Z', now)).toBe(10)
    expect(enrollmentSecondsRemaining('2026-07-28T23:59:59Z', now)).toBe(0)
    expect(enrollmentSecondsRemaining('invalid', now)).toBe(0)
  })
})
