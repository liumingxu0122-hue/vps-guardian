<script setup lang="ts">
import { Boxes, RefreshCw, Search } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { ServiceSummary } from '../types'
import { formatTime, titleize } from '../utils'

const services = ref<ServiceSummary[]>([])
const query = ref('')
const loading = ref(true)
const filtered = computed(() => {
  const needle = query.value.toLowerCase().trim()
  return services.value.filter((item) =>
    !needle || `${item.host_name} ${item.kind} ${item.summary}`.toLowerCase().includes(needle),
  )
})

async function load(): Promise<void> {
  loading.value = true
  try {
    services.value = await request<ServiceSummary[]>('/api/v1/services')
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <PageHeader title="服务" description="Agent 最近一次发现的 systemd、Docker、Compose 与监听状态">
    <template #actions><button class="icon-button bordered" type="button" title="刷新" aria-label="刷新服务" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="toolbar-row"><label class="search-field"><Search :size="16" /><input v-model="query" type="search" placeholder="搜索主机、类型或摘要" /></label><span>{{ filtered.length }} 项观察</span></div>
  <section v-if="filtered.length" class="service-grid">
    <article v-for="service in filtered" :key="`${service.host_id}-${service.kind}`" class="service-item">
      <div class="service-heading"><span class="service-icon"><Boxes :size="17" /></span><div><strong>{{ titleize(service.kind) }}</strong><span>{{ service.host_name }}</span></div><StatusBadge :status="service.status" /></div>
      <pre>{{ service.summary }}</pre>
      <small>采集于 {{ formatTime(service.collected_at) }}</small>
    </article>
  </section>
  <EmptyState v-else-if="!loading" title="尚未收到服务摘要" />
  <div v-else class="row-skeletons"><span v-for="item in 6" :key="item"></span></div>
</template>
