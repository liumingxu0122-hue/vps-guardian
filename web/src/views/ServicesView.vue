<script setup lang="ts">
import { Boxes, Plus, RefreshCw, Search, Trash2, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { session } from '../session'
import type { Agent, Host, ServiceCheck, ServiceSummary } from '../types'
import { formatTime, relativeTime, titleize } from '../utils'

const { t } = useI18n()
const checks = ref<ServiceCheck[]>([])
const observations = ref<ServiceSummary[]>([])
const hosts = ref<Host[]>([])
const agents = ref<Agent[]>([])
const query = ref('')
const loading = ref(true)
const error = ref('')
const creating = ref(false)
const dialog = ref<HTMLDialogElement | null>(null)
const canManage = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const newCheck = ref({
  name: '',
  kind: 'https' as ServiceCheck['kind'],
  target: '',
  port: 443,
  host_id: '',
  runner_agent_id: '',
  interval_seconds: 60,
  timeout_seconds: 5,
  failure_threshold: 3,
  recovery_threshold: 2,
  severity: 'warning' as ServiceCheck['severity'],
})
const filteredChecks = computed(() => {
  const needle = query.value.toLowerCase().trim()
  return checks.value.filter((check) =>
    !needle || `${check.name} ${check.kind} ${JSON.stringify(check.configuration)}`.toLowerCase().includes(needle),
  )
})
const filteredObservations = computed(() => {
  const needle = query.value.toLowerCase().trim()
  return observations.value.filter((item) =>
    !needle || `${item.host_name} ${item.kind} ${item.summary}`.toLowerCase().includes(needle),
  )
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const requests: [Promise<ServiceCheck[]>, Promise<ServiceSummary[]>] = [
      request<ServiceCheck[]>('/api/v1/service-checks'),
      request<ServiceSummary[]>('/api/v1/services'),
    ]
    ;[checks.value, observations.value] = await Promise.all(requests)
    if (canManage.value) {
      ;[hosts.value, agents.value] = await Promise.all([
        request<Host[]>('/api/v1/hosts'),
        request<Agent[]>('/api/v1/agents'),
      ])
    }
  } catch {
    error.value = t('services.fetchFailed')
  } finally {
    loading.value = false
  }
}

function configuration(): Record<string, unknown> {
  if (newCheck.value.kind === 'docker') return { container: newCheck.value.target }
  if (newCheck.value.kind === 'systemd') return { unit: newCheck.value.target }
  if (newCheck.value.kind === 'tcp') return { target: newCheck.value.target, port: newCheck.value.port }
  if (newCheck.value.kind === 'icmp') return { target: newCheck.value.target }
  return { target: newCheck.value.target, expected_statuses: [200], max_response_bytes: 65536 }
}

async function createCheck(): Promise<void> {
  creating.value = true
  try {
    await request<ServiceCheck>('/api/v1/service-checks', {
      method: 'POST',
      ...jsonBody({
        name: newCheck.value.name,
        kind: newCheck.value.kind,
        configuration: configuration(),
        host_id: newCheck.value.host_id || null,
        runner_agent_id: newCheck.value.runner_agent_id || null,
        interval_seconds: newCheck.value.interval_seconds,
        timeout_seconds: newCheck.value.timeout_seconds,
        failure_threshold: newCheck.value.failure_threshold,
        recovery_threshold: newCheck.value.recovery_threshold,
        severity: newCheck.value.severity,
      }),
    })
    dialog.value?.close()
    newCheck.value.name = ''
    newCheck.value.target = ''
    await load()
  } finally {
    creating.value = false
  }
}

async function deleteCheck(check: ServiceCheck): Promise<void> {
  await request<void>(`/api/v1/service-checks/${check.id}`, { method: 'DELETE' })
  await load()
}

onMounted(load)
</script>

<template>
  <PageHeader :title="t('services.title')" :description="t('services.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :title="t('common.refresh')" :aria-label="t('services.refresh')" @click="load"><RefreshCw :size="17" /></button>
      <button v-if="canManage" class="primary-button" type="button" @click="dialog?.showModal()"><Plus :size="16" />{{ t('services.add') }}</button>
    </template>
  </PageHeader>
  <div class="toolbar-row"><label class="search-field"><Search :size="16" /><input v-model="query" type="search" :placeholder="t('services.searchPlaceholder')" /></label><span>{{ t('services.checkCount', { count: filteredChecks.length }) }}</span></div>
  <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
  <div v-else-if="loading" class="row-skeletons" :aria-label="t('services.loading')"><span v-for="item in 6" :key="item"></span></div>
  <template v-else>
    <section class="section-block">
      <div class="section-heading"><div><h2>{{ t('services.configured') }}</h2><span>{{ t('services.configuredDescription') }}</span></div></div>
      <div v-if="filteredChecks.length" class="service-grid">
        <article v-for="check in filteredChecks" :key="check.id" class="service-item">
          <div class="service-heading"><span class="service-icon"><Boxes :size="17" /></span><div><strong>{{ check.name }}</strong><span>{{ titleize(check.kind) }} · {{ titleize(check.severity) }}</span></div><StatusBadge :status="check.enabled ? (check.last_checked_at ? 'observed' : 'unknown') : 'disabled'" /></div>
          <dl class="metric-facts"><div><dt>{{ t('services.interval') }}</dt><dd>{{ check.interval_seconds }}s</dd></div><div><dt>{{ t('services.threshold') }}</dt><dd>{{ check.failure_threshold }} / {{ check.recovery_threshold }}</dd></div><div><dt>{{ t('services.updated') }}</dt><dd>{{ relativeTime(check.last_checked_at) }}</dd></div></dl>
          <button v-if="canManage" class="icon-button danger" type="button" :title="t('services.delete')" :aria-label="t('services.delete')" @click="deleteCheck(check)"><Trash2 :size="16" /></button>
        </article>
      </div>
      <EmptyState v-else :title="t('services.noChecks')" />
    </section>
    <section class="section-block">
      <div class="section-heading"><div><h2>{{ t('services.observed') }}</h2><span>{{ t('services.observations', { count: filteredObservations.length }) }}</span></div></div>
      <div v-if="filteredObservations.length" class="service-grid">
        <article v-for="service in filteredObservations" :key="`${service.host_id}-${service.kind}`" class="service-item">
          <div class="service-heading"><span class="service-icon"><Boxes :size="17" /></span><div><strong>{{ titleize(service.kind) }}</strong><span>{{ service.host_name }}</span></div><StatusBadge :status="service.status" /></div>
          <pre>{{ service.summary }}</pre><small>{{ t('services.collectedAt', { time: formatTime(service.collected_at) }) }}</small>
        </article>
      </div>
      <EmptyState v-else :title="t('services.noServices')" />
    </section>
  </template>

  <dialog ref="dialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('services.addTitle') }}</h2><p>{{ t('services.addDescription') }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="createCheck">
      <div class="form-grid"><label><span>{{ t('services.name') }}</span><input v-model="newCheck.name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{1,119}" /></label><label><span>{{ t('services.kind') }}</span><select v-model="newCheck.kind"><option v-for="kind in ['http', 'https', 'tcp', 'icmp', 'docker', 'systemd']" :key="kind" :value="kind">{{ titleize(kind) }}</option></select></label></div>
      <label><span>{{ ['docker', 'systemd'].includes(newCheck.kind) ? t('services.registeredTarget') : t('services.target') }}</span><input v-model="newCheck.target" required /></label>
      <div class="form-grid"><label v-if="newCheck.kind === 'tcp'"><span>{{ t('services.port') }}</span><input v-model.number="newCheck.port" type="number" min="1" max="65535" required /></label><label><span>{{ t('services.runner') }}</span><select v-model="newCheck.runner_agent_id"><option value="">{{ t('services.controllerRunner') }}</option><option v-for="agent in agents" :key="agent.id" :value="agent.id">{{ hosts.find((host) => host.id === agent.host_id)?.name || agent.id }}</option></select></label><label v-if="['docker', 'systemd'].includes(newCheck.kind)"><span>{{ t('services.host') }}</span><select v-model="newCheck.host_id" required><option value="" disabled>{{ t('services.selectHost') }}</option><option v-for="host in hosts" :key="host.id" :value="host.id">{{ host.name }}</option></select></label></div>
      <div class="form-grid"><label><span>{{ t('services.interval') }}</span><input v-model.number="newCheck.interval_seconds" type="number" min="15" max="86400" /></label><label><span>{{ t('services.timeout') }}</span><input v-model.number="newCheck.timeout_seconds" type="number" min="1" max="30" /></label></div>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">{{ t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="creating">{{ creating ? t('services.creating') : t('services.create') }}</button></div>
    </form>
  </dialog>
</template>
