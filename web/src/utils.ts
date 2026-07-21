import { i18n } from './i18n'

const locale = (): string => i18n.global.locale.value

export function formatTime(value: string | null | undefined): string {
  if (!value) return i18n.global.t('common.none')
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return i18n.global.t('common.unknown')
  return new Intl.DateTimeFormat(locale(), {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
}

export function relativeTime(value: string | null | undefined): string {
  if (!value) return i18n.global.t('common.never')
  const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000)
  const formatter = new Intl.RelativeTimeFormat(locale(), { numeric: 'auto' })
  if (Math.abs(seconds) < 60) return formatter.format(seconds, 'second')
  const minutes = Math.round(seconds / 60)
  if (Math.abs(minutes) < 60) return formatter.format(minutes, 'minute')
  const hours = Math.round(minutes / 60)
  if (Math.abs(hours) < 24) return formatter.format(hours, 'hour')
  return formatter.format(Math.round(hours / 24), 'day')
}

export function formatBytes(value: unknown): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let amount = value
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024
    unit += 1
  }
  return `${new Intl.NumberFormat(locale(), { maximumFractionDigits: unit === 0 ? 0 : 1 }).format(amount)} ${units[unit]}`
}

export function formatDuration(value: unknown): string {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '—'
  const days = Math.floor(value / 86_400)
  const hours = Math.floor((value % 86_400) / 3_600)
  const minutes = Math.floor((value % 3_600) / 60)
  const unit = (amount: number, name: 'day' | 'hour' | 'minute'): string =>
    new Intl.NumberFormat(locale(), { style: 'unit', unit: name, unitDisplay: 'long' }).format(amount)
  if (days) return `${unit(days, 'day')} ${unit(hours, 'hour')}`
  if (hours) return `${unit(hours, 'hour')} ${unit(minutes, 'minute')}`
  return unit(minutes, 'minute')
}

export function percentUsed(total: unknown, free: unknown): number | null {
  if (typeof total !== 'number' || typeof free !== 'number' || total <= 0) return null
  return Math.max(0, Math.min(100, ((total - free) / total) * 100))
}

export function titleize(value: string): string {
  return value.replaceAll('_', ' ')
}
