<script setup lang="ts">
import { onMounted } from 'vue'
import { RouterView } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { session } from './session'
const { t } = useI18n()

onMounted(() => session.restore())
</script>

<template>
  <div v-if="!session.ready" class="boot-screen">
    <span class="boot-mark" aria-hidden="true"></span>
    <span>{{ t('app.connecting') }}</span>
  </div>
  <RouterView v-else />
</template>
