<script setup lang="ts">
import { RefreshCw, ShieldCheck } from '@lucide/vue'
import { onMounted } from 'vue'
import { RouterView } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { session } from './session'

const { locale } = useI18n()
async function restore(): Promise<void> {
  if (session.ready && session.error) {
    await session.retryRestore().catch(() => undefined)
    return
  }
  await session.restore().catch(() => undefined)
}

onMounted(() => void restore())
</script>

<template>
  <div v-if="!session.ready" class="v3-boot-app" aria-live="polite">
    <aside>
      <span><ShieldCheck :size="20" /></span>
      <div><strong>VPS Guardian</strong><small>{{ locale === 'zh-CN' ? '运维控制平面' : 'Operations control plane' }}</small></div>
    </aside>
    <header><i></i><strong>Staging</strong></header>
    <main>
      <div class="v3-boot-title"></div>
      <div class="v3-boot-summary"><span v-for="index in 5" :key="index"></span></div>
    </main>
    <p class="sr-only">{{ locale === 'zh-CN' ? '正在恢复会话' : 'Restoring session' }}</p>
  </div>
  <div v-else-if="session.error" class="v3-session-error" role="alert">
    <ShieldCheck :size="28" />
    <h1>{{ locale === 'zh-CN' ? '无法恢复会话' : 'Unable to restore session' }}</h1>
    <p>{{ locale === 'zh-CN' ? '认证服务返回了非预期错误。这不是“未登录”状态。' : 'The authentication service returned an unexpected error. This is not a signed-out state.' }}</p>
    <button class="proto-button secondary" type="button" @click="restore"><RefreshCw :size="15" />{{ locale === 'zh-CN' ? '重试' : 'Retry' }}</button>
  </div>
  <RouterView v-else />
</template>
