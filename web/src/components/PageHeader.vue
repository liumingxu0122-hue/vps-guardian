<script setup lang="ts">
import ProductPageHeader from './v3/PageHeader.vue'

defineProps<{ title: string; description?: string }>()
</script>

<template>
  <ProductPageHeader :title="title" :description="description">
    <template v-if="$slots.actions" #actions><slot name="actions" /></template>
  </ProductPageHeader>
</template>
