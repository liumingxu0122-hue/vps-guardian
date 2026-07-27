<script setup lang="ts">
import { BellRing, CheckCheck, CircleX, RefreshCw, UserCheck, VolumeX, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import DataTable from '../components/v3/DataTable.vue'
import { session } from '../session'
import type { Alert, AlertRule } from '../types'
import { productLabel } from '../presentationRegistry'
import { formatTime, relativeTime } from '../utils'

const { locale, t } = useI18n()
const alerts = ref<Alert[]>([])
const rules = ref<AlertRule[]>([])
const loading = ref(true)
const error = ref('')
const state = ref('active')
const silenceDialog = ref<HTMLDialogElement | null>(null)
const selected = ref<Alert | null>(null)
const selectedRow = ref<string | null>(null)
const silenceReason = ref('')
const silenceHours = ref(1)
const submitting = ref(false)
const canOperate = computed(() => ['operator', 'admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const ruleMap = computed(() => Object.fromEntries(rules.value.map((rule) => [rule.id, rule])))
const filtered = computed(() =>
  alerts.value.filter((alert) =>
    state.value === 'all'
      ? true
      : state.value === 'active'
        ? !['ok', 'resolved'].includes(alert.state)
        : alert.state === state.value,
  ),
)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    ;[alerts.value, rules.value] = await Promise.all([
      request<Alert[]>('/api/v1/alerts'),
      request<AlertRule[]>('/api/v1/alert-rules'),
    ])
  } catch {
    error.value = t('alerts.fetchFailed')
  } finally {
    loading.value = false
  }
}

async function acknowledge(alert: Alert): Promise<void> {
  submitting.value = true
  try {
    await request<Alert>(`/api/v1/alerts/${alert.id}/acknowledge`, { method: 'POST' })
    await load()
  } finally {
    submitting.value = false
  }
}

function openSilence(alert: Alert): void {
  selected.value = alert
  silenceReason.value = ''
  silenceHours.value = 1
  silenceDialog.value?.showModal()
}

async function silence(): Promise<void> {
  if (!selected.value) return
  submitting.value = true
  try {
    await request<Alert>(`/api/v1/alerts/${selected.value.id}/silence`, {
      method: 'POST',
      ...jsonBody({
        reason: silenceReason.value,
        until: new Date(Date.now() + silenceHours.value * 3_600_000).toISOString(),
      }),
    })
    silenceDialog.value?.close()
    await load()
  } finally {
    submitting.value = false
  }
}

async function assignToMe(alert: Alert): Promise<void> {
  if (!session.user) return
  submitting.value = true
  try {
    await request<Alert>(`/api/v1/alerts/${alert.id}`, {
      method: 'PATCH',
      ...jsonBody({ assigned_to: session.user.id, note: 'assigned from alert center' }),
    })
    await load()
  } finally {
    submitting.value = false
  }
}

async function closeAlert(alert: Alert): Promise<void> {
  submitting.value = true
  try {
    await request<Alert>(`/api/v1/alerts/${alert.id}`, {
      method: 'PATCH',
      ...jsonBody({ assigned_to: alert.assigned_to, close: true, note: 'verified and closed' }),
    })
    await load()
  } finally {
    submitting.value = false
  }
}

onMounted(load)
</script>

<template>
  <PageHeader :title="t('alerts.title')" :description="t('alerts.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :title="t('common.refresh')" :aria-label="t('alerts.refresh')" @click="load"><RefreshCw :size="17" /></button>
    </template>
  </PageHeader>
  <div class="toolbar-row">
    <label><span class="sr-only">{{ t('alerts.stateFilter') }}</span><select v-model="state" :aria-label="t('alerts.stateFilter')"><option value="active">{{ t('alerts.active') }}</option><option value="all">{{ t('alerts.all') }}</option><option value="firing">{{ t('alerts.firing') }}</option><option value="acknowledged">{{ t('alerts.acknowledged') }}</option><option value="silenced">{{ t('alerts.silenced') }}</option><option value="resolved">{{ t('alerts.resolved') }}</option></select></label>
    <span>{{ t('alerts.count', { count: filtered.length }) }}</span>
  </div>
  <DataTable :label="t('alerts.title')" :loading="loading" :error="error" :empty="!filtered.length" :total="filtered.length" @retry="load">
    <template #head><tr><th>{{ locale === 'zh-CN' ? '状态' : 'State' }}</th><th>{{ locale === 'zh-CN' ? '告警' : 'Alert' }}</th><th>{{ locale === 'zh-CN' ? '摘要' : 'Summary' }}</th><th>{{ locale === 'zh-CN' ? '等级' : 'Severity' }}</th><th>{{ locale === 'zh-CN' ? '更新时间' : 'Updated' }}</th><th>{{ locale === 'zh-CN' ? '处理人' : 'Responder' }}</th><th>{{ locale === 'zh-CN' ? '操作' : 'Actions' }}</th></tr></template>
    <tr v-for="alert in filtered" :key="alert.id" :class="{ 'is-selected': selectedRow === alert.id }" :aria-selected="selectedRow === alert.id" tabindex="0" @click="selectedRow = alert.id" @keydown.enter="selectedRow = alert.id">
      <td><StatusBadge :status="alert.state" /></td>
      <td><span class="rc5-resource"><span class="rc5-resource-icon"><BellRing :size="18" /></span><strong>{{ ruleMap[alert.rule_id]?.name || t('alerts.unknownRule') }}</strong></span></td>
      <td><strong>{{ alert.summary }}</strong><small v-if="alert.silenced_until">{{ t('alerts.silencedUntil', { time: formatTime(alert.silenced_until) }) }}</small></td>
      <td>{{ productLabel('severity', ruleMap[alert.rule_id]?.severity || 'warning', locale) }}</td>
      <td>{{ relativeTime(alert.last_observed_at) }}</td>
      <td>{{ alert.assigned_to ? (locale === 'zh-CN' ? '已指派' : 'Assigned') : (locale === 'zh-CN' ? '待指派' : 'Unassigned') }}</td>
      <td><div v-if="canOperate && alert.state !== 'closed'" class="alert-actions" @click.stop>
        <button v-if="!alert.assigned_to" class="secondary-button" type="button" :disabled="submitting" @click="assignToMe(alert)"><UserCheck :size="15" />{{ t('alerts.assignMe') }}</button>
        <button v-if="['pending', 'firing'].includes(alert.state)" class="secondary-button" type="button" :disabled="submitting" @click="acknowledge(alert)"><CheckCheck :size="15" />{{ t('alerts.acknowledge') }}</button>
        <button v-if="['pending', 'firing', 'acknowledged'].includes(alert.state)" class="secondary-button" type="button" :disabled="submitting" @click="openSilence(alert)"><VolumeX :size="15" />{{ t('alerts.silence') }}</button>
        <button v-if="['acknowledged', 'resolved'].includes(alert.state)" class="secondary-button" type="button" :disabled="submitting" @click="closeAlert(alert)"><CircleX :size="15" />{{ t('alerts.closeAlert') }}</button>
      </div></td>
    </tr>
    <template #empty><EmptyState :title="t('alerts.noItems')" /></template>
  </DataTable>

  <dialog ref="silenceDialog" class="modal-dialog compact">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('alerts.silenceTitle') }}</h2><p>{{ selected?.summary }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="silence">
      <label><span>{{ t('alerts.reason') }}</span><input v-model="silenceReason" required minlength="3" maxlength="255" /></label>
      <label><span>{{ t('alerts.duration') }}</span><input v-model.number="silenceHours" type="number" min="1" max="720" required /></label>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="silenceDialog?.close()">{{ t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="submitting">{{ t('alerts.confirmSilence') }}</button></div>
    </form>
  </dialog>
</template>
