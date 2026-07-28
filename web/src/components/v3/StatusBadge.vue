<script setup lang="ts">
import { AlertTriangle, Check, CircleDot, Info, XCircle } from '@lucide/vue'
import { computed } from 'vue'

export type StatusTone = 'healthy' | 'warning' | 'critical' | 'info' | 'neutral'

const props = defineProps<{
  tone: StatusTone
  label: string
  compact?: boolean
}>()

const icon = computed(() => {
  if (props.tone === 'healthy') return Check
  if (props.tone === 'warning') return AlertTriangle
  if (props.tone === 'critical') return XCircle
  if (props.tone === 'info') return Info
  return CircleDot
})
</script>

<template>
  <span class="proto-status" :class="[`is-${tone}`, { compact }]">
    <component :is="icon" :size="compact ? 13 : 14" aria-hidden="true" />
    <span>{{ label }}</span>
  </span>
</template>
