import { afterEach, describe, expect, it, vi } from 'vitest'

import { i18n, initialLocale, missingTranslation, normalizeLocale, setLocale } from './i18n'
import enUS from './locales/en-US'
import zhCN from './locales/zh-CN'
import { PSEUDO_LOCALE, pseudoLocalize, pseudoMessages } from './pseudoLocale'

function keys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return [prefix]
  return Object.entries(value).flatMap(([key, child]) =>
    keys(child, prefix ? `${prefix}.${key}` : key),
  )
}

function interpolationParameters(value: unknown, prefix = ''): Record<string, string[]> {
  if (typeof value === 'string') {
    return {
      [prefix]: [...value.matchAll(/\{([A-Za-z0-9_]+)\}/g)]
        .map((match) => match[1] ?? '')
        .sort(),
    }
  }
  if (!value || typeof value !== 'object') return {}
  return Object.fromEntries(
    Object.entries(value).flatMap(([key, child]) =>
      Object.entries(interpolationParameters(child, prefix ? `${prefix}.${key}` : key)),
    ),
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

  it('use matching interpolation parameters in both locales', () => {
    expect(interpolationParameters(zhCN)).toEqual(interpolationParameters(enUS))
  })

  it.each([
    'pending',
    'partially_approved',
    'approved',
    'approved_with_conditions',
    'changes_requested',
    'rejected',
    'expired',
    'withdrawn',
    'executing',
    'executed',
    'failed',
    'rolled_back',
  ])('localizes approval status %s', (status) => {
    expect(enUS.status[status as keyof typeof enUS.status]).toBeTruthy()
    expect(zhCN.status[status as keyof typeof zhCN.status]).toBeTruthy()
  })
})

describe('locale selection', () => {
  afterEach(() => vi.unstubAllGlobals())
  it.each(['zh-CN', 'zh-SG', 'zh'])('selects Chinese for %s', (locale) => {
    expect(normalizeLocale(locale)).toBe('zh-CN')
  })

  it('selects English for an English browser locale', () => {
    expect(normalizeLocale('en-US')).toBe('en-US')
  })

  it.each(['de-DE', 'ja-JP', 'zh-Hant', undefined])('defaults unsupported %s to Chinese', (locale) => {
    expect(normalizeLocale(locale)).toBe('zh-CN')
  })

  it('prefers a persisted locale over the browser locale', () => {
    expect(initialLocale('en-US', 'zh-CN')).toBe('en-US')
    expect(initialLocale('zh-CN', 'en-US')).toBe('zh-CN')
  })

  it('persists only a long-lived non-auth locale cookie on HTTPS', () => {
    const documentStub = { cookie: '', documentElement: { lang: '' } }
    vi.stubGlobal('document', documentStub)
    vi.stubGlobal('location', { protocol: 'https:' })

    setLocale('en-US')

    expect(documentStub.cookie).toContain('guardian_locale=en-US')
    expect(documentStub.cookie).toContain('Max-Age=31536000')
    expect(documentStub.cookie).toContain('SameSite=Lax')
    expect(documentStub.cookie).toContain('Secure')
    expect(documentStub.cookie).not.toContain('HttpOnly')
    expect(documentStub.documentElement.lang).toBe('en-US')
  })

  it('uses a safe localized placeholder instead of exposing a missing key', () => {
    expect(missingTranslation('zh-CN')).toBe('翻译暂不可用')
    expect(missingTranslation('en-US')).toBe('Translation unavailable')
    i18n.global.locale.value = 'en-US'
    expect(i18n.global.t('this.key.does.not.exist')).toBe('Translation unavailable')
  })

  it('uses natural English recovery-code plurals', () => {
    i18n.global.locale.value = 'en-US'
    expect(i18n.global.t('accountSecurity.remaining', { count: 0 })).toBe(
      'No unused recovery codes remain.',
    )
    expect(i18n.global.t('accountSecurity.remaining', { count: 1 })).toBe(
      'One unused recovery code remains.',
    )
    expect(i18n.global.t('accountSecurity.remaining', { count: 8 })).toBe(
      '8 unused recovery codes remain.',
    )
  })
})

describe('test-only pseudo locale', () => {
  it('expands and brackets source text so clipping is visible', () => {
    expect(PSEUDO_LOCALE).toBe('en-XA')
    expect(pseudoLocalize('Language')).toBe('[!! Laanguuaagee !!]')
    expect(keys(pseudoMessages).sort()).toEqual(keys(enUS).sort())
  })
})
