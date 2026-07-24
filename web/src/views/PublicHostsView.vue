<script setup lang="ts">
import { MapPin, RefreshCw, Search, Server } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import EmptyState from '../components/EmptyState.vue'
import MetricBar from '../components/MetricBar.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { request } from '../api'
import type { PublicHost } from '../types'
import { relativeTime } from '../utils'

const { t } = useI18n()
const hosts = ref<PublicHost[]>([])
const query = ref('')
const loading = ref(true)
const error = ref('')
const filtered = computed(() => {
  const needle = query.value.trim().toLocaleLowerCase()
  return hosts.value.filter((host) =>
    !needle || [host.name, host.location ?? ''].some((value) => value.toLocaleLowerCase().includes(needle)),
  )
})

async function load(): Promise<void> {
  error.value = ''
  try {
    hosts.value = await request<PublicHost[]>('/api/v1/public/hosts')
  } catch {
    error.value = t('publicPanel.fetchFailed')
  } finally {
    loading.value = false
  }
}

onMounted(() => void load())
</script>

<template>
  <PageHeader :title="t('hosts.title')" :description="t('publicPanel.hostsDescription')">
    <template #actions>
      <button class="icon-button bordered" type="button" :aria-label="t('common.refresh')" @click="load"><RefreshCw :size="17" /></button>
    </template>
  </PageHeader>
  <div class="toolbar-row">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" :placeholder="t('publicPanel.searchPlaceholder')" /></label>
    <span>{{ filtered.length }} / {{ hosts.length }}</span>
  </div>
  <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
  <div v-else-if="loading" class="row-skeletons" :aria-label="t('hosts.loading')"><span v-for="item in 6" :key="item"></span></div>
  <section v-else class="host-list">
    <article v-for="host in filtered" :key="host.name" class="host-item expanded">
      <div class="host-summary">
        <span class="host-icon"><Server :size="19" /></span>
        <span class="host-identity"><strong>{{ host.name }}</strong><small>{{ t('publicPanel.redacted') }}</small></span>
        <span class="host-location"><MapPin :size="14" />{{ host.location || t('hosts.notSet') }}</span>
        <StatusBadge :status="host.data_state" />
        <span class="last-seen">{{ relativeTime(host.last_seen_at) }}</span>
      </div>
      <div class="host-detail">
        <MetricBar label="CPU" :value="host.resources.cpu_percent" />
        <MetricBar :label="t('hosts.memory')" :value="host.resources.memory_percent" />
        <MetricBar :label="t('hosts.disk')" :value="host.resources.disk_percent" />
      </div>
    </article>
    <EmptyState v-if="!filtered.length" :title="t('hosts.noMatch')" />
  </section>
</template>
