import { createI18n } from 'vue-i18n'

import enUS from './locales/en-US'
import zhCN from './locales/zh-CN'

export type SupportedLocale = 'en-US' | 'zh-CN'
export const DEFAULT_LOCALE: SupportedLocale = 'zh-CN'
export const LOCALE_STORAGE_KEY = 'guardian_locale'
export const LOCALE_COOKIE_MAX_AGE = 31_536_000

export function missingTranslation(locale: string): string {
  return normalizeLocale(locale) === 'zh-CN' ? '翻译暂不可用' : 'Translation unavailable'
}

function localeCookie(): string | null {
  if (typeof document === 'undefined') return null
  const value = document.cookie
    .split('; ')
    .find((item) => item.startsWith(`${LOCALE_STORAGE_KEY}=`))
  return value ? decodeURIComponent(value.slice(LOCALE_STORAGE_KEY.length + 1)) : null
}

export function normalizeLocale(value: string | null | undefined): SupportedLocale {
  const normalized = value?.trim().toLowerCase()
  if (normalized === 'zh' || normalized === 'zh-cn' || normalized === 'zh-sg') return 'zh-CN'
  if (normalized === 'en' || normalized?.startsWith('en-')) return 'en-US'
  return DEFAULT_LOCALE
}

export function initialLocale(
  stored = localeCookie(),
  browserLocale = typeof navigator === 'undefined' ? undefined : navigator.languages?.[0] ?? navigator.language,
): SupportedLocale {
  if (stored === 'en-US' || stored === 'zh-CN') return stored
  return normalizeLocale(browserLocale)
}

export const i18n = createI18n({
  legacy: false,
  locale: initialLocale(),
  fallbackLocale: false,
  messages: { 'en-US': enUS, 'zh-CN': zhCN },
  missing: (locale) => missingTranslation(locale),
  missingWarn: true,
  fallbackWarn: true,
})
if (typeof document !== 'undefined') document.documentElement.lang = i18n.global.locale.value

if (
  import.meta.env.DEV
  && typeof location !== 'undefined'
  && new URLSearchParams(location.search).get('__locale') === 'en-XA'
) {
  void import('./pseudoLocale').then(({ PSEUDO_LOCALE, pseudoMessages }) => {
    i18n.global.setLocaleMessage(PSEUDO_LOCALE, pseudoMessages as typeof enUS)
    ;(i18n.global.locale as { value: string }).value = PSEUDO_LOCALE
    if (typeof document !== 'undefined') document.documentElement.lang = PSEUDO_LOCALE
  })
}

export function setLocale(locale: SupportedLocale): void {
  i18n.global.locale.value = locale
  if (typeof document !== 'undefined') document.documentElement.lang = locale
  if (typeof document !== 'undefined') {
    const secure = location.protocol === 'https:' ? '; Secure' : ''
    document.cookie = `${LOCALE_STORAGE_KEY}=${encodeURIComponent(locale)}; Path=/; Max-Age=${LOCALE_COOKIE_MAX_AGE}; SameSite=Lax${secure}`
  }
}

export function translateStatus(value: string): string {
  const key = `status.${value}`
  return i18n.global.te(key) ? i18n.global.t(key) : value.replaceAll('_', ' ')
}

export function apiErrorKey(status: number, code?: string): string {
  if (code && i18n.global.te(`errors.${code}`)) return `errors.${code}`
  if (status === 401) return 'errors.unauthorized'
  if (status === 403) return 'errors.forbidden'
  if (status >= 500) return 'errors.unavailable'
  return 'errors.requestFailed'
}
