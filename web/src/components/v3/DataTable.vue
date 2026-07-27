<script setup lang="ts">
import { computed, ref } from 'vue'

const props = withDefaults(defineProps<{
  label: string
  tableClass?: string
  selectedKey?: string | number | null
  density?: 'compact' | 'comfortable'
  loading?: boolean
  empty?: boolean
  error?: string
  page?: number
  pageSize?: number
  total?: number
  stickyHeader?: boolean
  virtualized?: boolean
}>(), {
  density: 'comfortable',
  loading: false,
  empty: false,
  error: '',
  page: 1,
  pageSize: 100,
  total: 0,
  stickyHeader: true,
  virtualized: false,
  tableClass: '',
})
const emit = defineEmits<{ previous: []; next: []; retry: [] }>()
const region = ref<HTMLElement | null>(null)
const pageCount = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))

function onKeydown(event: KeyboardEvent): void {
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
  const rows = [...(region.value?.querySelectorAll<HTMLElement>('tbody tr[tabindex]') ?? [])]
  if (!rows.length) return
  const current = Math.max(0, rows.indexOf(document.activeElement as HTMLElement))
  const target = event.key === 'Home'
    ? 0
    : event.key === 'End'
      ? rows.length - 1
      : Math.min(rows.length - 1, Math.max(0, current + (event.key === 'ArrowDown' ? 1 : -1)))
  event.preventDefault()
  rows[target]?.focus()
}
</script>

<template>
  <div ref="region" class="rc5-data-region" :class="[`density-${density}`, { 'has-sticky-header': stickyHeader, virtualized }]" @keydown="onKeydown">
    <div v-if="error" class="rc5-table-state" role="alert"><strong>{{ error }}</strong><button type="button" class="secondary-button" @click="emit('retry')">Retry</button></div>
    <div v-else-if="loading" class="rc5-table-state" aria-live="polite"><span v-for="row in 5" :key="row" class="rc5-table-skeleton"></span></div>
    <div v-else-if="empty" class="rc5-table-state"><slot name="empty">No matching records.</slot></div>
    <table v-else class="rc5-data-table" :class="tableClass" :aria-label="label" :aria-rowcount="total || undefined">
      <thead><slot name="head"></slot></thead>
      <tbody><slot></slot></tbody>
    </table>
    <footer v-if="total > pageSize" class="rc5-table-pagination">
      <span>{{ page }} / {{ pageCount }}</span>
      <div><button type="button" class="secondary-button" :disabled="page <= 1" @click="emit('previous')">Previous</button><button type="button" class="secondary-button" :disabled="page >= pageCount" @click="emit('next')">Next</button></div>
    </footer>
  </div>
</template>
