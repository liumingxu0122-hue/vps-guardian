import enUS from './locales/en-US'

export const PSEUDO_LOCALE = 'en-XA' as const

export function pseudoLocalize(value: string): string {
  const expanded = value.replace(/[AEIOUaeiou]/g, (character) => `${character}${character}`)
  return `[!! ${expanded} !!]`
}

function transform(value: unknown): unknown {
  if (typeof value === 'string') return pseudoLocalize(value)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.entries(value).map(([key, child]) => [key, transform(child)]),
  )
}

export const pseudoMessages = transform(enUS)
