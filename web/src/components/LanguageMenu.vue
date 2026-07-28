<script setup lang="ts">
import { Check, ChevronDown, Globe2 } from '@lucide/vue'
import { nextTick, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { setLocale, type SupportedLocale } from '../i18n'

const { locale, t } = useI18n()
const open = ref(false)
const trigger = ref<HTMLButtonElement | null>(null)
const menu = ref<HTMLElement | null>(null)
const options: SupportedLocale[] = ['zh-CN', 'en-US']

function label(value: SupportedLocale): string {
  return value === 'zh-CN' ? t('locale.chinese') : t('locale.english')
}

async function show(): Promise<void> {
  open.value = true
  await nextTick()
  menu.value
    ?.querySelector<HTMLButtonElement>(`[data-locale="${locale.value}"]`)
    ?.focus()
}

function close(restoreFocus = true): void {
  open.value = false
  if (restoreFocus) void nextTick(() => trigger.value?.focus())
}

function choose(value: SupportedLocale): void {
  setLocale(value)
  close()
}

function onMenuKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    event.preventDefault()
    close()
    return
  }
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
  const controls = [...(menu.value?.querySelectorAll<HTMLButtonElement>('[role="menuitemradio"]') ?? [])]
  if (!controls.length) return
  const current = Math.max(0, controls.indexOf(document.activeElement as HTMLButtonElement))
  const target = event.key === 'Home'
    ? 0
    : event.key === 'End'
      ? controls.length - 1
      : (current + (event.key === 'ArrowDown' ? 1 : -1) + controls.length) % controls.length
  event.preventDefault()
  controls[target]?.focus()
}

function onDocumentPointerDown(event: PointerEvent): void {
  if (!open.value || (event.target instanceof Node && menu.value?.parentElement?.contains(event.target))) return
  close(false)
}

function onDocumentKeydown(event: KeyboardEvent): void {
  if (open.value && event.key === 'Escape') {
    event.preventDefault()
    close()
  }
}

document.addEventListener('pointerdown', onDocumentPointerDown)
document.addEventListener('keydown', onDocumentKeydown)
onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', onDocumentPointerDown)
  document.removeEventListener('keydown', onDocumentKeydown)
})
</script>

<template>
  <div class="language-menu">
    <button
      ref="trigger"
      class="language-menu-trigger"
      type="button"
      :aria-label="t('locale.select')"
      aria-haspopup="menu"
      :aria-expanded="open"
      @click="open ? close() : show()"
    >
      <Globe2 :size="17" aria-hidden="true" />
      <span>{{ label(locale as SupportedLocale) }}</span>
      <ChevronDown :size="14" aria-hidden="true" />
    </button>
    <div
      v-if="open"
      ref="menu"
      class="language-menu-popover"
      role="menu"
      :aria-label="t('locale.select')"
      @keydown="onMenuKeydown"
    >
      <button
        v-for="option in options"
        :key="option"
        type="button"
        role="menuitemradio"
        :data-locale="option"
        :aria-checked="locale === option"
        @click="choose(option)"
      >
        <span><strong>{{ label(option) }}</strong><small>{{ option }}</small></span>
        <Check v-if="locale === option" :size="16" aria-hidden="true" />
      </button>
    </div>
  </div>
</template>
