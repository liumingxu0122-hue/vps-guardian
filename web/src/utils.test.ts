import { describe, expect, it } from 'vitest'

import { formatBytes, formatDuration, percentUsed, titleize } from './utils'

describe('operational formatters', () => {
  it('formats byte values without losing scale', () => {
    expect(formatBytes(1536)).toBe('1.5 KB')
    expect(formatBytes(undefined)).toBe('—')
  })

  it('clamps usage percentages', () => {
    expect(percentUsed(100, 25)).toBe(75)
    expect(percentUsed(100, -10)).toBe(100)
    expect(percentUsed(0, 0)).toBeNull()
  })

  it('turns identifiers into readable labels', () => {
    expect(titleize('reverse_proxy_backend')).toBe('reverse proxy backend')
  })

  it('formats host uptime as a duration', () => {
    expect(formatDuration(90_000)).toBe('1天 1小时')
  })
})
