<script setup lang="ts">
import { ChevronRight, RefreshCw, Search, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { Incident } from '../types'
import { formatTime, titleize } from '../utils'

const incidents = ref<Incident[]>([])
const { t } = useI18n()
const stateOptions = computed(() => [['active', t('incidents.active')], ['resolved', t('incidents.resolved')], ['all', t('common.all')]])
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
  <PageHeader :title="t('incidents.title')" :description="t('incidents.description')">
    <template #actions><button class="icon-button bordered" type="button" :title="t('common.refresh')" :aria-label="t('incidents.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="toolbar-row incident-toolbar">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" :placeholder="t('incidents.searchPlaceholder')" /></label>
    <div class="segmented-control"><button v-for="option in stateOptions" :key="option[0]" type="button" :class="{ active: state === option[0] }" @click="state = option[0]">{{ option[1] }}</button></div>
  </div>
  <div class="split-view" :class="{ 'detail-open': selected }">
    <section class="incident-list">
      <button v-for="incident in filtered" :key="incident.id" class="incident-row" type="button" :class="{ selected: selected?.id === incident.id }" @click="selected = incident">
        <span class="severity" :class="`severity-${incident.severity}`">S{{ incident.severity }}</span>
        <span class="incident-main"><strong>{{ incident.title }}</strong><small class="mono">{{ titleize(incident.fault_type) }}</small></span>
        <span class="confidence">{{ Math.round(incident.confidence * 100) }}%<small>{{ t('incidents.confidence') }}</small></span>
        <StatusBadge :status="incident.status" />
        <span class="muted">{{ formatTime(incident.first_seen_at) }}</span>
        <ChevronRight :size="16" />
      </button>
      <EmptyState v-if="!filtered.length" :title="t('incidents.noItems')" />
    </section>
    <aside v-if="selected" class="detail-panel">
      <header><div><span class="mono">{{ selected.id.slice(0, 8) }}</span><h2>{{ selected.title }}</h2></div><button class="icon-button" type="button" :aria-label="t('incidents.closeDetail')" @click="selected = null"><X :size="18" /></button></header>
      <div class="detail-meta"><StatusBadge :status="selected.status" /><span>{{ t('incidents.risk', { value: selected.risk }) }}</span><span>{{ t('incidents.confidenceValue', { value: Math.round(selected.confidence * 100) }) }}</span></div>
      <section><h3>{{ t('incidents.impact') }}</h3><div class="tag-list"><span v-for="host in selected.affected_hosts" :key="host">{{ host }}</span><span v-for="service in selected.affected_services" :key="service">{{ service }}</span></div></section>
      <section><h3>{{ t('incidents.evidence') }}</h3><dl class="evidence-list"><div v-for="(evidence, index) in selected.evidence" :key="index"><dt>{{ evidence.source ?? t('incidents.evidenceItem', { number: index + 1 }) }}</dt><dd>{{ evidence.observation ?? JSON.stringify(evidence.value ?? evidence) }}</dd></div></dl></section>
      <section><h3>{{ t('incidents.excluded') }}</h3><ul><li v-for="cause in selected.excluded_causes" :key="cause">{{ cause }}</li></ul></section>
      <section><h3>{{ t('incidents.verification') }}</h3><ol><li v-for="step in selected.verification_plan" :key="step">{{ step }}</li></ol></section>
    </aside>
  </div>
</template>
