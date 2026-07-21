<script setup lang="ts">
import { Inbox } from '@lucide/vue'

defineProps<{ title: string; detail?: string }>()
</script>

<template>
  <div class="empty-state">
    <Inbox :size="22" aria-hidden="true" />
    <strong>{{ title }}</strong>
    <span v-if="detail">{{ detail }}</span>
  </div>
</template>
