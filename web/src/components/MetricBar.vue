<script setup lang="ts">
defineProps<{ label: string; value: number | null; detail?: string }>()
</script>

<template>
  <div class="metric-bar">
    <div class="metric-label">
      <span>{{ label }}</span>
      <span>{{ value === null ? '—' : `${value.toFixed(1)}%` }} <small>{{ detail }}</small></span>
    </div>
    <div class="metric-track" aria-hidden="true">
      <span
        :class="{ caution: value !== null && value >= 75, danger: value !== null && value >= 90 }"
        :style="{ width: `${value ?? 0}%` }"
      ></span>
    </div>
  </div>
</template>
