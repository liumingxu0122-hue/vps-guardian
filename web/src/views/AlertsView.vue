<script setup lang="ts">
import { BellRing, CheckCheck, Clock3, RefreshCw, VolumeX, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { session } from '../session'
import type { Alert, AlertRule } from '../types'
import { formatTime, relativeTime, titleize } from '../utils'

const { t } = useI18n()
const alerts = ref<Alert[]>([])
const rules = ref<AlertRule[]>([])
const loading = ref(true)
const error = ref('')
const state = ref('active')
const silenceDialog = ref<HTMLDialogElement | null>(null)
const selected = ref<Alert | null>(null)
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
  <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
  <div v-else-if="loading" class="row-skeletons" :aria-label="t('alerts.loading')"><span v-for="item in 5" :key="item"></span></div>
  <section v-else-if="filtered.length" class="alert-list">
    <article v-for="alert in filtered" :key="alert.id" class="alert-item">
      <div class="alert-icon"><BellRing :size="18" /></div>
      <div class="alert-copy">
        <div><strong>{{ ruleMap[alert.rule_id]?.name || t('alerts.unknownRule') }}</strong><StatusBadge :status="alert.state" /></div>
        <p>{{ alert.summary }}</p>
        <span><Clock3 :size="13" />{{ t('alerts.updated', { time: relativeTime(alert.last_observed_at) }) }} · {{ titleize(ruleMap[alert.rule_id]?.severity || 'warning') }}</span>
      </div>
      <div v-if="canOperate && ['pending', 'firing'].includes(alert.state)" class="alert-actions">
        <button class="secondary-button" type="button" :disabled="submitting" @click="acknowledge(alert)"><CheckCheck :size="15" />{{ t('alerts.acknowledge') }}</button>
        <button class="secondary-button" type="button" :disabled="submitting" @click="openSilence(alert)"><VolumeX :size="15" />{{ t('alerts.silence') }}</button>
      </div>
      <small v-if="alert.silenced_until">{{ t('alerts.silencedUntil', { time: formatTime(alert.silenced_until) }) }}</small>
    </article>
  </section>
  <EmptyState v-else :title="t('alerts.noItems')" />

  <dialog ref="silenceDialog" class="modal-dialog compact">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('alerts.silenceTitle') }}</h2><p>{{ selected?.summary }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="silence">
      <label><span>{{ t('alerts.reason') }}</span><input v-model="silenceReason" required minlength="3" maxlength="255" /></label>
      <label><span>{{ t('alerts.duration') }}</span><input v-model.number="silenceHours" type="number" min="1" max="720" required /></label>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="silenceDialog?.close()">{{ t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="submitting">{{ t('alerts.confirmSilence') }}</button></div>
    </form>
  </dialog>
</template>
