<script setup lang="ts">
import { X } from '@lucide/vue'
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  open: boolean
  eyebrow: string
  title: string
}>()
const emit = defineEmits<{ close: [] }>()
const { t } = useI18n()
const drawer = ref<HTMLElement | null>(null)
let previousFocus: HTMLElement | null = null

function focusableElements(): HTMLElement[] {
  if (!drawer.value) return []
  return Array.from(
    drawer.value.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  )
}

function onKeydown(event: KeyboardEvent): void {
  if (!props.open) return
  if (event.key === 'Escape') {
    event.preventDefault()
    emit('close')
    return
  }
  if (event.key !== 'Tab') return
  const focusable = focusableElements()
  if (!focusable.length) {
    event.preventDefault()
    drawer.value?.focus()
    return
  }
  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}

watch(
  () => props.open,
  async (open) => {
    document.body.classList.toggle('prototype-lock-scroll', open && innerWidth <= 560)
    if (open) {
      previousFocus = document.activeElement as HTMLElement | null
      await nextTick()
      drawer.value?.focus()
    } else {
      previousFocus?.focus()
      previousFocus = null
    }
  },
)

onMounted(() => window.addEventListener('keydown', onKeydown))
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKeydown)
  document.body.classList.remove('prototype-lock-scroll')
})
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="proto-drawer-scrim" aria-hidden="true" @click="emit('close')"></div>
    <aside
      v-if="open"
      ref="drawer"
      class="proto-detail-drawer"
      role="dialog"
      aria-modal="true"
      :aria-label="title"
      tabindex="-1"
    >
      <header>
        <div>
          <p>{{ eyebrow }}</p>
          <h2>{{ title }}</h2>
        </div>
        <button class="proto-icon-button" type="button" :aria-label="t('common.close')" @click="emit('close')">
          <X :size="19" />
        </button>
      </header>
      <slot></slot>
    </aside>
  </Teleport>
</template>
