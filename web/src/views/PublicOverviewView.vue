<script setup lang="ts">
import { Activity, RefreshCw, Server } from '@lucide/vue'
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useI18n } from 'vue-i18n'

import EmptyState from '../components/EmptyState.vue'
import MetricBar from '../components/MetricBar.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { request } from '../api'
import type { PublicOverview } from '../types'
import { formatTime, relativeTime } from '../utils'

const { t } = useI18n()
const data = ref<PublicOverview | null>(null)
const loading = ref(true)
const error = ref('')
let pollTimer: number | undefined

async function load(): Promise<void> {
  error.value = ''
  try {
    data.value = await request<PublicOverview>('/api/v1/public/overview')
  } catch {
    error.value = t('publicPanel.fetchFailed')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void load()
  pollTimer = window.setInterval(() => {
    if (document.visibilityState === 'visible' && navigator.onLine) void load()
  }, 60_000)
})

onBeforeUnmount(() => {
  if (pollTimer) window.clearInterval(pollTimer)
})
</script>

<template>
  <PageHeader :title="t('publicPanel.title')" :description="t('publicPanel.description')">
    <template #actions>
      <span class="context-pill staging">{{ t('publicPanel.badge') }}</span>
      <button class="icon-button bordered" type="button" :aria-label="t('common.refresh')" @click="load">
        <RefreshCw :size="17" />
      </button>
    </template>
  </PageHeader>
  <div class="overview-notice warning" role="status">{{ t('publicPanel.notice') }}</div>
  <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
  <template v-else-if="data">
    <section class="operations-status" :aria-label="t('overview.globalHealth')">
      <div class="status-metric" :class="`health-${data.global_health}`">
        <Activity :size="18" />
        <span>{{ t('overview.globalHealth') }}</span>
        <strong>{{ t(`status.${data.global_health}`) }}</strong>
        <small>{{ formatTime(data.generated_at) }}</small>
      </div>
      <div class="status-metric">
        <Server :size="18" />
        <span>{{ t('overview.onlineHosts') }}</span>
        <strong>{{ data.hosts.healthy }} / {{ data.hosts.total }}</strong>
        <small>{{ data.hosts.degraded }} {{ t('status.degraded') }} · {{ data.hosts.offline }} {{ t('status.offline') }}</small>
      </div>
    </section>
    <section class="overview-section hosts-section">
      <header class="overview-section-heading">
        <div><h2>{{ t('overview.vpsList') }}</h2><span>{{ t('overview.managedHosts', { count: data.host_rows.length }) }}</span></div>
        <RouterLink to="/hosts">{{ t('overview.fullList') }}</RouterLink>
      </header>
      <div v-if="data.host_rows.length" class="operations-host-table public-host-table">
        <div class="operations-host-head public-host-row"><span>{{ t('overview.host') }}</span><span>{{ t('overview.status') }}</span><span>CPU</span><span>{{ t('overview.memory') }}</span><span>{{ t('overview.disk') }}</span><span>{{ t('overview.heartbeat') }}</span></div>
        <div v-for="host in data.host_rows" :key="host.name" class="operations-host-row public-host-row">
          <span class="ops-host-name"><strong>{{ host.name }}</strong><small>{{ host.location || t('overview.regionMissing') }}</small></span>
          <StatusBadge :status="host.status" />
          <span>{{ host.resources.cpu_percent === null ? '—' : `${host.resources.cpu_percent.toFixed(1)}%` }}</span>
          <span>{{ host.resources.memory_percent === null ? '—' : `${host.resources.memory_percent.toFixed(1)}%` }}</span>
          <span>{{ host.resources.disk_percent === null ? '—' : `${host.resources.disk_percent.toFixed(1)}%` }}</span>
          <span>{{ relativeTime(host.last_seen_at) }}</span>
        </div>
      </div>
      <EmptyState v-else :title="t('overview.noHosts')" />
    </section>
  </template>
  <div v-else-if="loading" class="overview-loading" :aria-label="t('overview.loading')">
    <span v-for="item in 6" :key="item"></span>
  </div>
</template>
