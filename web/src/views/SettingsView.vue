<script setup lang="ts">
import { Check, LockKeyhole, RefreshCw, ShieldCheck, X } from '@lucide/vue'
import { onMounted, ref } from 'vue'

import { request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import type { PublicSettings } from '../types'
import { formatBytes, titleize } from '../utils'

const settings = ref<PublicSettings | null>(null)
async function load(): Promise<void> { settings.value = await request<PublicSettings>('/api/v1/settings/public') }
onMounted(load)
</script>

<template>
  <PageHeader :title="$t('settings.title')" :description="$t('settings.description')">
    <template #actions><button class="icon-button bordered" type="button" :title="$t('common.refresh')" :aria-label="$t('settings.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div v-if="settings" class="settings-layout">
    <section class="settings-section">
      <div class="section-heading"><div><h2>{{ $t('settings.runtime') }}</h2><span>{{ $t('settings.readOnly') }}</span></div><span class="environment-badge">{{ settings.environment }}</span></div>
      <dl class="settings-list">
        <div><dt>{{ $t('settings.secureCookies') }}</dt><dd><Check v-if="settings.secure_cookies" :size="16" /><X v-else :size="16" />{{ settings.secure_cookies ? $t('common.enabled') : $t('common.disabled') }}</dd></div>
        <div><dt>{{ $t('settings.autoSchema') }}</dt><dd>{{ settings.auto_create_schema ? $t('common.enabled') : $t('common.disabled') }}</dd></div>
        <div><dt>{{ $t('settings.logLimit') }}</dt><dd>{{ formatBytes(settings.max_incident_log_bytes) }}</dd></div>
        <div><dt>{{ $t('settings.loginAttempts') }}</dt><dd>{{ $t('settings.attempts', { count: settings.login_attempts_per_10m }) }}</dd></div>
        <div><dt>{{ $t('settings.nonceTtl') }}</dt><dd>{{ settings.nonce_ttl_seconds }} {{ $t('common.seconds') }}</dd></div>
        <div><dt>{{ $t('settings.allowedOrigins') }}</dt><dd class="mono wrap">{{ settings.allowed_origins.join(', ') }}</dd></div>
      </dl>
    </section>
    <section class="settings-section">
      <div class="section-heading"><div><h2>{{ $t('settings.securityBoundary') }}</h2><span>{{ $t('settings.serverEnforced') }}</span></div><ShieldCheck :size="19" /></div>
      <div class="feature-grid">
        <div v-for="(enabled, name) in settings.features" :key="name" :class="{ disabled: !enabled }"><span><LockKeyhole :size="16" />{{ titleize(String(name)) }}</span><strong>{{ enabled ? $t('common.enabled') : $t('common.disabled') }}</strong></div>
      </div>
    </section>
  </div>
</template>
