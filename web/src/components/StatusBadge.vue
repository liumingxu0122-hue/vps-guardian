<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ status: string; label?: string }>()
const tone = computed(() => {
  if (['healthy', 'resolved', 'approved', 'executed', 'success', 'verified'].includes(props.status)) {
    return 'positive'
  }
  if (['degraded', 'investigating', 'pending', 'dry_run_only', 'observed'].includes(props.status)) {
    return 'warning'
  }
  if (['offline', 'open', 'failed', 'rejected', 'denied'].includes(props.status)) {
    return 'negative'
  }
  return 'neutral'
})
</script>

<template>
  <span class="status-badge" :class="`status-${tone}`">
    <span class="status-dot" aria-hidden="true"></span>
    {{ label ?? status }}
  </span>
</template>
