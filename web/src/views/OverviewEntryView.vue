<script setup lang="ts">
import { computed, defineAsyncComponent } from 'vue'

import { session } from '../session'

const view = computed(() =>
  session.publicReadOnly
    ? defineAsyncComponent(() => import('./PublicOverviewView.vue'))
    : defineAsyncComponent(() => import('./OverviewView.vue')),
)
</script>

<template>
  <component :is="view" />
</template>
