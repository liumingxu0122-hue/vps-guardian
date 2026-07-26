<script setup lang="ts">
defineProps<{
  eyebrow?: string
  title: string
  description?: string
  updated?: string
}>()
</script>

<template>
  <header class="proto-page-header">
    <div>
      <p v-if="eyebrow" class="proto-eyebrow">{{ eyebrow }}</p>
      <h1>{{ title }}</h1>
      <p v-if="description">{{ description }}</p>
    </div>
    <div class="proto-page-actions">
      <span v-if="updated">{{ updated }}</span>
      <slot name="actions"></slot>
    </div>
  </header>
</template>
