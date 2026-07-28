import { describe, expect, it } from 'vitest'

import { i18n } from './i18n'

import {
  formatBytes,
  formatDuration,
  formatTime,
  percentUsed,
  relativeTime,
  titleize,
} from './utils'

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
    i18n.global.locale.value = 'zh-CN'
    expect(formatDuration(90_000)).toBe('1天 1小时')
    i18n.global.locale.value = 'en-US'
    expect(formatDuration(90_000)).toBe('1 day 1 hour')
  })

  it('updates date and relative-time presentation with the runtime locale', () => {
    i18n.global.locale.value = 'zh-CN'
    const chineseDate = formatTime('2026-07-28T12:35:00Z')
    const chineseRelative = relativeTime(new Date(Date.now() + 86_400_000).toISOString())
    i18n.global.locale.value = 'en-US'
    const englishDate = formatTime('2026-07-28T12:35:00Z')
    const englishRelative = relativeTime(new Date(Date.now() + 86_400_000).toISOString())

    expect(chineseDate).toContain('2026')
    expect(englishDate).toContain('2026')
    expect(chineseDate).not.toBe(englishDate)
    expect(chineseRelative).not.toBe(englishRelative)
  })
})
