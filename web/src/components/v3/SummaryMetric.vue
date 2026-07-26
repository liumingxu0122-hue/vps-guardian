<script setup lang="ts">
import { ChevronRight } from '@lucide/vue'

import StatusBadge, { type StatusTone } from './StatusBadge.vue'

defineProps<{
  label: string
  value: string
  detail: string
  updated: string
  tone: StatusTone
  statusLabel: string
}>()
</script>

<template>
  <button class="proto-summary" type="button">
    <span class="proto-summary-head">
      <span>{{ label }}</span>
      <StatusBadge :tone="tone" :label="statusLabel" compact />
    </span>
    <strong>{{ value }}</strong>
    <span>{{ detail }}</span>
    <small>{{ updated }} <ChevronRight :size="13" /></small>
  </button>
</template>
