<script setup lang="ts">
import { ChevronRight, RefreshCw, Search, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { Incident } from '../types'
import { formatTime, titleize } from '../utils'

const incidents = ref<Incident[]>([])
const selected = ref<Incident | null>(null)
const query = ref('')
const state = ref('active')
const filtered = computed(() => incidents.value.filter((incident) => {
  const statusMatch = state.value === 'all' || (state.value === 'active' ? incident.status !== 'resolved' : incident.status === 'resolved')
  const needle = query.value.toLowerCase().trim()
  return statusMatch && (!needle || `${incident.title} ${incident.fault_type}`.toLowerCase().includes(needle))
}))

async function load(): Promise<void> {
  incidents.value = await request<Incident[]>('/api/v1/incidents')
  if (selected.value) selected.value = incidents.value.find((item) => item.id === selected.value?.id) ?? null
}

onMounted(load)
</script>

<template>
  <PageHeader title="事故" description="确定性诊断、证据链与恢复时间线">
    <template #actions><button class="icon-button bordered" type="button" title="刷新" aria-label="刷新事故" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="toolbar-row incident-toolbar">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" placeholder="搜索事故或故障类型" /></label>
    <div class="segmented-control"><button v-for="option in [['active','活动'],['resolved','已解决'],['all','全部']]" :key="option[0]" type="button" :class="{ active: state === option[0] }" @click="state = option[0]">{{ option[1] }}</button></div>
  </div>
  <div class="split-view" :class="{ 'detail-open': selected }">
    <section class="incident-list">
      <button v-for="incident in filtered" :key="incident.id" class="incident-row" type="button" :class="{ selected: selected?.id === incident.id }" @click="selected = incident">
        <span class="severity" :class="`severity-${incident.severity}`">S{{ incident.severity }}</span>
        <span class="incident-main"><strong>{{ incident.title }}</strong><small class="mono">{{ titleize(incident.fault_type) }}</small></span>
        <span class="confidence">{{ Math.round(incident.confidence * 100) }}%<small>置信度</small></span>
        <StatusBadge :status="incident.status" />
        <span class="muted">{{ formatTime(incident.first_seen_at) }}</span>
        <ChevronRight :size="16" />
      </button>
      <EmptyState v-if="!filtered.length" title="没有匹配的事故" />
    </section>
    <aside v-if="selected" class="detail-panel">
      <header><div><span class="mono">{{ selected.id.slice(0, 8) }}</span><h2>{{ selected.title }}</h2></div><button class="icon-button" type="button" aria-label="关闭详情" @click="selected = null"><X :size="18" /></button></header>
      <div class="detail-meta"><StatusBadge :status="selected.status" /><span>风险：{{ selected.risk }}</span><span>置信度 {{ Math.round(selected.confidence * 100) }}%</span></div>
      <section><h3>影响范围</h3><div class="tag-list"><span v-for="host in selected.affected_hosts" :key="host">{{ host }}</span><span v-for="service in selected.affected_services" :key="service">{{ service }}</span></div></section>
      <section><h3>诊断证据</h3><dl class="evidence-list"><div v-for="(evidence, index) in selected.evidence" :key="index"><dt>{{ evidence.source ?? `证据 ${index + 1}` }}</dt><dd>{{ evidence.observation ?? JSON.stringify(evidence.value ?? evidence) }}</dd></div></dl></section>
      <section><h3>已排除原因</h3><ul><li v-for="cause in selected.excluded_causes" :key="cause">{{ cause }}</li></ul></section>
      <section><h3>验证计划</h3><ol><li v-for="step in selected.verification_plan" :key="step">{{ step }}</li></ol></section>
    </aside>
  </div>
</template>
