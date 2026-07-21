import { describe, expect, it } from 'vitest'

import { initialLocale, normalizeLocale } from './i18n'
import enUS from './locales/en-US'
import zhCN from './locales/zh-CN'

function keys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return [prefix]
  return Object.entries(value).flatMap(([key, child]) =>
    keys(child, prefix ? `${prefix}.${key}` : key),
  )
}

describe('locale resources', () => {
  it('have exactly matching keys', () => {
    expect(keys(zhCN).sort()).toEqual(keys(enUS).sort())
  })

  it('contain no empty translations', () => {
    expect(keys(enUS)).not.toContain('')
    expect(JSON.stringify(enUS)).not.toContain('""')
    expect(JSON.stringify(zhCN)).not.toContain('""')
  })
})

describe('locale selection', () => {
  it.each(['zh-CN', 'zh-Hans', 'zh-Hant', 'zh'])('selects Chinese for %s', (locale) => {
    expect(normalizeLocale(locale)).toBe('zh-CN')
  })

  it.each(['en-US', 'de-DE', 'ja-JP', undefined])('defaults %s to English', (locale) => {
    expect(normalizeLocale(locale)).toBe('en-US')
  })

  it('prefers a persisted locale over the browser locale', () => {
    expect(initialLocale('en-US', 'zh-CN')).toBe('en-US')
    expect(initialLocale('zh-CN', 'en-US')).toBe('zh-CN')
  })
})
