<script setup lang="ts">
import { computed } from 'vue'
import { translateStatus } from '../i18n'
import ProductStatusBadge, { type StatusTone } from './v3/StatusBadge.vue'

const props = defineProps<{ status: string; label?: string }>()
const tone = computed<StatusTone>(() => {
  if (['healthy', 'resolved', 'approved', 'executed', 'success', 'verified', 'enabled', 'delivered'].includes(props.status)) {
    return 'healthy'
  }
  if (['degraded', 'investigating', 'pending', 'dry_run_only', 'observed'].includes(props.status)) {
    return 'warning'
  }
  if (['offline', 'open', 'failed', 'rejected', 'denied'].includes(props.status)) {
    return 'critical'
  }
  if (['info', 'acknowledged', 'silenced', 'running'].includes(props.status)) return 'info'
  return 'neutral'
})
</script>

<template>
  <ProductStatusBadge :tone="tone" :label="label ?? translateStatus(status)" compact />
</template>
