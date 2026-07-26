<script setup lang="ts">
import { CheckCircle2, RefreshCw, ShieldAlert, ShieldCheck } from '@lucide/vue'
import { onMounted, ref } from 'vue'

import { request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { DashboardSecurity } from '../dashboard'
import type { User } from '../types'
import { formatTime, titleize } from '../utils'

const security = ref<DashboardSecurity | null>(null)
const users = ref<User[]>([])
const error = ref('')
async function load(): Promise<void> {
  error.value = ''
  try {
    ;[security.value, users.value] = await Promise.all([
      request<DashboardSecurity>('/api/v1/dashboard/security'),
      request<User[]>('/api/v1/users'),
    ])
  } catch {
    error.value = 'Security summary is temporarily unavailable.'
  }
}
onMounted(load)
</script>

<template>
  <PageHeader :title="$t('security.title')" :description="$t('security.description')">
    <template #actions><button class="icon-button bordered" type="button" :aria-label="$t('common.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div v-if="error" class="v3-module-state error-state" role="alert"><strong>{{ error }}</strong><button class="proto-button secondary" type="button" @click="load">Retry</button></div>
  <template v-if="security">
    <section class="security-summary-grid">
      <article><ShieldAlert :size="18" /><span>Uncovered Critical</span><strong>{{ security.controls.uncovered_critical ?? '—' }}</strong></article>
      <article><ShieldAlert :size="18" /><span>Uncovered High</span><strong>{{ security.controls.uncovered_high ?? '—' }}</strong></article>
      <article><ShieldCheck :size="18" /><span>Last scan</span><strong>{{ formatTime(security.controls.last_scan_at) }}</strong></article>
      <article><ShieldCheck :size="18" /><span>Owner TOTP</span><strong>{{ users.filter((user) => user.role === 'owner' && user.totp_enabled).length }} / {{ users.filter((user) => user.role === 'owner').length }}</strong></article>
    </section>
    <section class="settings-section">
      <div class="section-heading"><div><h2>{{ $t('security.controls') }}</h2><span>{{ $t('security.serverEnforced') }}</span></div></div>
      <div class="security-control-table">
        <div v-for="(value, key) in security.controls" :key="key">
          <CheckCircle2 :size="16" /><strong>{{ titleize(String(key)) }}</strong>
          <StatusBadge v-if="typeof value === 'string' && !String(key).endsWith('_at')" :status="String(value)" />
          <span v-else>{{ value ?? $t('common.unknown') }}</span>
        </div>
      </div>
    </section>
  </template>
</template>
