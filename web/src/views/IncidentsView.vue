<script setup lang="ts">
import { CheckCircle2, ChevronRight, RefreshCw, Search, UserCheck, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { session } from '../session'
import type { Incident } from '../types'
import { formatTime, titleize } from '../utils'

const incidents = ref<Incident[]>([])
const { t } = useI18n()
const stateOptions = computed(() => [['active', t('incidents.active')], ['resolved', t('incidents.resolved')], ['all', t('common.all')]])
const selected = ref<Incident | null>(null)
const query = ref('')
const state = ref('active')
const note = ref('')
const resolution = ref('')
const postmortem = ref('')
const submitting = ref(false)
const canOperate = computed(() => ['operator', 'admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const filtered = computed(() => incidents.value.filter((incident) => {
  const statusMatch = state.value === 'all' || (state.value === 'active' ? incident.status !== 'resolved' : incident.status === 'resolved')
  const needle = query.value.toLowerCase().trim()
  return statusMatch && (!needle || `${incident.title} ${incident.fault_type}`.toLowerCase().includes(needle))
}))

async function load(): Promise<void> {
  incidents.value = await request<Incident[]>('/api/v1/incidents')
  if (selected.value) selected.value = incidents.value.find((item) => item.id === selected.value?.id) ?? null
}

async function updateIncident(
  status: Incident['status'] | null,
  assignedTo = selected.value?.assigned_to ?? null,
): Promise<void> {
  if (!selected.value) return
  submitting.value = true
  try {
    selected.value = await request<Incident>(`/api/v1/incidents/${selected.value.id}`, {
      method: 'PATCH',
      ...jsonBody({
        status,
        assigned_to: assignedTo,
        note: note.value,
        resolution_summary: status === 'resolved' ? resolution.value : null,
        postmortem: status === 'resolved' && postmortem.value ? postmortem.value : null,
      }),
    })
    note.value = ''
    await load()
  } finally {
    submitting.value = false
  }
}

function nextStates(incident: Incident): Incident['status'][] {
  if (incident.status === 'open') return ['acknowledged', 'investigating']
  if (incident.status === 'acknowledged') return ['investigating']
  if (incident.status === 'investigating') return ['mitigating', 'resolved']
  if (incident.status === 'mitigating') return ['investigating', 'resolved']
  return []
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
      <section v-if="canOperate" class="incident-workflow">
        <h3>{{ t('incidents.workflow') }}</h3>
        <div class="workflow-owner"><span>{{ selected.assigned_to ? t('incidents.assigned', { id: selected.assigned_to.slice(0, 8) }) : t('incidents.unassigned') }}</span><button v-if="session.user && selected.assigned_to !== session.user.id" class="secondary-button" type="button" :disabled="submitting" @click="updateIncident(null, session.user.id)"><UserCheck :size="14" />{{ t('incidents.assignMe') }}</button></div>
        <label><span>{{ t('incidents.note') }}</span><textarea v-model="note" maxlength="1000"></textarea></label>
        <template v-if="nextStates(selected).includes('resolved')">
          <label><span>{{ t('incidents.resolutionSummary') }}</span><textarea v-model="resolution" maxlength="4000"></textarea></label>
          <label><span>{{ t('incidents.postmortem') }}</span><textarea v-model="postmortem" maxlength="20000"></textarea></label>
        </template>
        <div class="workflow-actions">
          <button v-for="next in nextStates(selected)" :key="next" class="secondary-button" type="button" :disabled="submitting || (next === 'resolved' && resolution.trim().length < 3)" @click="updateIncident(next)">
            <CheckCircle2 :size="14" />{{ t('incidents.moveTo', { status: titleize(next) }) }}
          </button>
        </div>
      </section>
      <section><h3>{{ t('incidents.impact') }}</h3><div class="tag-list"><span v-for="host in selected.affected_hosts" :key="host">{{ host }}</span><span v-for="service in selected.affected_services" :key="service">{{ service }}</span></div></section>
      <section><h3>{{ t('incidents.evidence') }}</h3><dl class="evidence-list"><div v-for="(evidence, index) in selected.evidence" :key="index"><dt>{{ evidence.source ?? t('incidents.evidenceItem', { number: index + 1 }) }}</dt><dd>{{ evidence.observation ?? JSON.stringify(evidence.value ?? evidence) }}</dd></div></dl></section>
      <section><h3>{{ t('incidents.excluded') }}</h3><ul><li v-for="cause in selected.excluded_causes" :key="cause">{{ cause }}</li></ul></section>
      <section><h3>{{ t('incidents.verification') }}</h3><ol><li v-for="step in selected.verification_plan" :key="step">{{ step }}</li></ol></section>
      <section><h3>{{ t('incidents.timeline') }}</h3><ol class="incident-timeline"><li v-for="(entry, index) in selected.timeline" :key="index"><strong>{{ String(entry.from ?? '—') }} → {{ String(entry.to ?? '—') }}</strong><span>{{ String(entry.note ?? '') }}</span><time>{{ formatTime(String(entry.at ?? '')) }}</time></li></ol></section>
    </aside>
  </div>
</template>
