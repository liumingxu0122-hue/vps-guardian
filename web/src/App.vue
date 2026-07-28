<script setup lang="ts">
import { RefreshCw, ShieldCheck } from '@lucide/vue'
import { onBeforeUnmount, onMounted } from 'vue'
import { RouterView } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { installActivityTracking, session } from './session'

const { t } = useI18n()
async function restore(): Promise<void> {
  if (session.ready && session.error) {
    await session.retryRestore().catch(() => undefined)
    return
  }
  await session.restore().catch(() => undefined)
}

let removeActivityTracking: (() => void) | null = null
onMounted(() => {
  removeActivityTracking = installActivityTracking()
  void restore()
})
onBeforeUnmount(() => removeActivityTracking?.())
</script>

<template>
  <div v-if="!session.ready" class="v3-boot-app" aria-live="polite">
    <aside>
      <span><ShieldCheck :size="20" /></span>
      <div><strong>VPS Guardian</strong><small>{{ t('app.controlPlane') }}</small></div>
    </aside>
    <header><i></i><strong>{{ t('app.staging') }}</strong></header>
    <main>
      <div class="v3-boot-title"></div>
      <div class="v3-boot-summary"><span v-for="index in 5" :key="index"></span></div>
    </main>
    <p class="sr-only">{{ t('app.restoringSession') }}</p>
  </div>
  <div v-else-if="session.error" class="v3-session-error" role="alert">
    <ShieldCheck :size="28" />
    <h1>{{ t('app.restoreFailed') }}</h1>
    <p>{{ t('app.restoreUnexpected') }}</p>
    <button class="proto-button secondary" type="button" @click="restore"><RefreshCw :size="15" />{{ t('common.retry') }}</button>
  </div>
  <RouterView v-else />
</template>
