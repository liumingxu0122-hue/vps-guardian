import { createI18n } from 'vue-i18n'

import enUS from './locales/en-US'
import zhCN from './locales/zh-CN'

export type SupportedLocale = 'en-US' | 'zh-CN'
export const DEFAULT_LOCALE: SupportedLocale = 'en-US'
export const LOCALE_STORAGE_KEY = 'guardian_locale'

export function normalizeLocale(value: string | null | undefined): SupportedLocale {
  if (value && /^(zh)(?:-|$)/i.test(value)) return 'zh-CN'
  return DEFAULT_LOCALE
}

export function initialLocale(
  stored = typeof localStorage === 'undefined' ? null : localStorage.getItem(LOCALE_STORAGE_KEY),
  browserLocale = typeof navigator === 'undefined' ? undefined : navigator.languages?.[0] ?? navigator.language,
): SupportedLocale {
  if (stored === 'en-US' || stored === 'zh-CN') return stored
  return normalizeLocale(browserLocale)
}

export const i18n = createI18n({
  legacy: false,
  locale: initialLocale(),
  fallbackLocale: DEFAULT_LOCALE,
  messages: { 'en-US': enUS, 'zh-CN': zhCN },
  missingWarn: true,
  fallbackWarn: true,
})

export function setLocale(locale: SupportedLocale): void {
  i18n.global.locale.value = locale
  if (typeof document !== 'undefined') document.documentElement.lang = locale
  if (typeof localStorage !== 'undefined') localStorage.setItem(LOCALE_STORAGE_KEY, locale)
}

export function translateStatus(value: string): string {
  const key = `status.${value}`
  return i18n.global.te(key) ? i18n.global.t(key) : value.replaceAll('_', ' ')
}

export function apiErrorKey(status: number): string {
  if (status === 401) return 'errors.unauthorized'
  if (status === 403) return 'errors.forbidden'
  if (status >= 500) return 'errors.unavailable'
  return 'errors.requestFailed'
}
