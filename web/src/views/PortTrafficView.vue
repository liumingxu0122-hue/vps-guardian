<script setup lang="ts">
import { AlertTriangle, Plus, RefreshCw, RotateCcw, ShieldCheck } from '@lucide/vue'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import { session } from '../session'
import type {
  HostPresentation,
  PortTrafficHistory,
  PortTrafficPolicy,
  PortTrafficSummary,
} from '../types'
import { formatBytes } from '../utils'

const { locale, t } = useI18n()
const hosts = ref<HostPresentation[]>([])
const selectedHost = ref('')
const policies = ref<PortTrafficPolicy[]>([])
const selectedPolicy = ref('')
const summary = ref<PortTrafficSummary | null>(null)
const history = ref<PortTrafficHistory | null>(null)
const loading = ref(false)
const error = ref('')
const notice = ref('')
const createDialog = ref<HTMLDialogElement | null>(null)
const editDialog = ref<HTMLDialogElement | null>(null)
const changeDialog = ref<HTMLDialogElement | null>(null)
const resetDialog = ref<HTMLDialogElement | null>(null)
const historyRange = ref<'today' | '1h' | '24h' | '7d' | '30d' | '90d'>('24h')
const newPolicy = ref({
  name: '',
  protocol: 'tcp',
  direction: 'both',
  port_start: 443,
  port_end: 443,
  interface_name: '',
  quota_gib: 0,
})
const change = ref({
  mode: 'monitor_only',
  rate_mbps: 0,
  reason: '',
  reset_type: 'manual',
  reset_timezone: 'UTC',
  reset_day: 1,
  reset_month: 1,
  reset_every: 1,
  reset_anchor: new Date().toISOString().slice(0, 10),
  reset_date: new Date().toISOString().slice(0, 10),
})
const reset = ref({ reason: '', confirmation: '' })
const edit = ref({ name: '', quota_gib: 0, enabled: true })

const canManage = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const activePolicy = computed(() => policies.value.find((item) => item.id === selectedPolicy.value) ?? null)

function localTime(value: string | null): string {
  if (!value) return t('common.never')
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZoneName: 'short',
  }).format(new Date(value))
}

function bytes(value: number | null): string {
  return value == null ? t('portTraffic.noData') : formatBytes(value)
}

async function loadHosts(): Promise<void> {
  hosts.value = await request<HostPresentation[]>('/api/v1/hosts/presentation')
  if (!selectedHost.value && hosts.value.length) selectedHost.value = hosts.value[0].id
}

async function loadPolicies(): Promise<void> {
  if (!selectedHost.value) return
  loading.value = true
  error.value = ''
  try {
    policies.value = await request<PortTrafficPolicy[]>(
      `/api/v1/hosts/${selectedHost.value}/port-traffic/policies`,
    )
    if (!policies.value.some((item) => item.id === selectedPolicy.value)) {
      selectedPolicy.value = policies.value[0]?.id ?? ''
    }
    await loadDetails()
  } catch {
    error.value = t('portTraffic.loadFailed')
  } finally {
    loading.value = false
  }
}

async function loadDetails(): Promise<void> {
  summary.value = null
  history.value = null
  if (!selectedHost.value || !selectedPolicy.value) return
  const ends = new Date()
  const starts = new Date(ends)
  if (historyRange.value === 'today') starts.setHours(0, 0, 0, 0)
  else {
    const hours = { '1h': 1, '24h': 24, '7d': 24 * 7, '30d': 24 * 30, '90d': 24 * 90 }[historyRange.value]
    starts.setTime(ends.getTime() - hours * 60 * 60 * 1000)
  }
  ;[summary.value, history.value] = await Promise.all([
    request<PortTrafficSummary>(
      `/api/v1/hosts/${selectedHost.value}/port-traffic/policies/${selectedPolicy.value}/summary`,
    ),
    request<PortTrafficHistory>(
      `/api/v1/hosts/${selectedHost.value}/port-traffic/policies/${selectedPolicy.value}/history`
      + `?starts_at=${encodeURIComponent(starts.toISOString())}&ends_at=${encodeURIComponent(ends.toISOString())}`,
    ),
  ])
}

function openEdit(): void {
  if (!activePolicy.value) return
  edit.value = {
    name: activePolicy.value.name,
    quota_gib: activePolicy.value.quota_bytes == null
      ? 0
      : activePolicy.value.quota_bytes / (1024 * 1024 * 1024),
    enabled: activePolicy.value.enabled,
  }
  editDialog.value?.showModal()
}

async function updatePolicy(): Promise<void> {
  if (!activePolicy.value) return
  error.value = ''
  try {
    await request(
      `/api/v1/hosts/${selectedHost.value}/port-traffic/policies/${activePolicy.value.id}`,
      {
        method: 'PATCH',
        ...jsonBody({
          name: edit.value.name,
          quota_bytes: edit.value.quota_gib > 0
            ? Math.round(edit.value.quota_gib * 1024 * 1024 * 1024)
            : null,
          enabled: edit.value.enabled,
        }),
      },
    )
    editDialog.value?.close()
    notice.value = t('portTraffic.updatePending')
    await loadPolicies()
  } catch {
    error.value = t('portTraffic.updateFailed')
  }
}

async function createPolicy(): Promise<void> {
  error.value = ''
  const quota = newPolicy.value.quota_gib > 0
    ? Math.round(newPolicy.value.quota_gib * 1024 * 1024 * 1024)
    : null
  try {
    await request(`/api/v1/hosts/${selectedHost.value}/port-traffic/policies`, {
      method: 'POST',
      ...jsonBody({
        name: newPolicy.value.name,
        protocol: newPolicy.value.protocol,
        direction: newPolicy.value.direction,
        port_start: newPolicy.value.port_start,
        port_end: newPolicy.value.port_end,
        interface_name: newPolicy.value.interface_name || null,
        quota_bytes: quota,
        mode: 'monitor_only',
      }),
    })
    createDialog.value?.close()
    notice.value = t('portTraffic.monitorPending')
    await loadPolicies()
  } catch {
    error.value = t('portTraffic.createFailed')
  }
}

async function requestChange(): Promise<void> {
  if (!activePolicy.value) return
  error.value = ''
  try {
    await request(
      `/api/v1/hosts/${selectedHost.value}/port-traffic/policies/${activePolicy.value.id}/change-requests`,
      {
        method: 'POST',
        ...jsonBody({
          mode: change.value.mode,
          egress_rate_bps: change.value.rate_mbps > 0
            ? Math.round(change.value.rate_mbps * 1_000_000)
            : null,
          reset_policy: resetPolicyPayload(),
          reason: change.value.reason,
        }),
      },
    )
    changeDialog.value?.close()
    notice.value = t('portTraffic.approvalPending')
  } catch {
    error.value = t('portTraffic.changeFailed')
  }
}

function openChange(): void {
  if (!activePolicy.value) return
  const policy = activePolicy.value.reset_policy
  const stringValue = (key: string, fallback: string): string =>
    typeof policy[key] === 'string' ? String(policy[key]) : fallback
  const numberValue = (key: string, fallback: number): number =>
    typeof policy[key] === 'number' ? Number(policy[key]) : fallback
  change.value = {
    mode: activePolicy.value.mode,
    rate_mbps: (activePolicy.value.egress_rate_bps ?? 0) / 1_000_000,
    reason: '',
    reset_type: stringValue('type', 'manual'),
    reset_timezone: stringValue(
      'timezone',
      Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    ),
    reset_day: numberValue('day', 1),
    reset_month: numberValue('month', 1),
    reset_every: numberValue('every', 1),
    reset_anchor: stringValue('anchor_date', new Date().toISOString().slice(0, 10)),
    reset_date: stringValue('date', new Date().toISOString().slice(0, 10)),
  }
  changeDialog.value?.showModal()
}

function resetPolicyPayload(): Record<string, string | number> {
  const base = { type: change.value.reset_type, timezone: change.value.reset_timezone }
  if (change.value.reset_type === 'manual') return base
  if (change.value.reset_type === 'monthly') {
    return { ...base, day: change.value.reset_day }
  }
  if (change.value.reset_type === 'interval_days') {
    return { ...base, every: change.value.reset_every, anchor_date: change.value.reset_anchor }
  }
  if (change.value.reset_type === 'interval_months') {
    return {
      ...base,
      every: change.value.reset_every,
      day: change.value.reset_day,
      anchor_date: change.value.reset_anchor,
    }
  }
  if (change.value.reset_type === 'yearly') {
    return { ...base, month: change.value.reset_month, day: change.value.reset_day }
  }
  return { ...base, date: change.value.reset_date }
}

function openReset(): void {
  if (!activePolicy.value) return
  reset.value = {
    reason: '',
    confirmation: `RESET ${activePolicy.value.id}`,
  }
  resetDialog.value?.showModal()
}

async function requestReset(): Promise<void> {
  if (!activePolicy.value) return
  try {
    await request(
      `/api/v1/hosts/${selectedHost.value}/port-traffic/policies/${activePolicy.value.id}/reset-requests`,
      { method: 'POST', ...jsonBody(reset.value) },
    )
    resetDialog.value?.close()
    notice.value = t('portTraffic.resetApprovalPending')
  } catch {
    error.value = t('portTraffic.resetFailed')
  }
}

watch(selectedHost, loadPolicies)
watch(selectedPolicy, loadDetails)
watch(historyRange, loadDetails)
onMounted(async () => {
  try {
    await loadHosts()
    await loadPolicies()
  } catch {
    error.value = t('portTraffic.loadFailed')
  }
})
</script>

<template>
  <PageHeader :title="$t('portTraffic.title')" :description="$t('portTraffic.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :aria-label="$t('common.refresh')" @click="loadPolicies">
        <RefreshCw :size="17" />
      </button>
      <button v-if="canManage" class="primary-button" type="button" :disabled="!selectedHost" @click="createDialog?.showModal()">
        <Plus :size="16" />{{ $t('portTraffic.addPolicy') }}
      </button>
    </template>
  </PageHeader>

  <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
  <p v-if="notice" class="traffic-notice" role="status">{{ notice }}</p>
  <section class="traffic-toolbar" aria-label="Traffic filters">
    <label>
      <span>{{ $t('portTraffic.host') }}</span>
      <select v-model="selectedHost">
        <option v-for="host in hosts" :key="host.id" :value="host.id">{{ host.name }}</option>
      </select>
    </label>
    <label>
      <span>{{ $t('portTraffic.policy') }}</span>
      <select v-model="selectedPolicy" :disabled="!policies.length">
        <option v-for="policy in policies" :key="policy.id" :value="policy.id">
          {{ policy.name }} · {{ policy.protocol.toUpperCase() }} {{ policy.port_start }}–{{ policy.port_end }}
        </option>
      </select>
    </label>
  </section>

  <div v-if="loading" class="empty-panel">{{ $t('common.loading') }}</div>
  <div v-else-if="!activePolicy" class="empty-panel">{{ $t('portTraffic.empty') }}</div>
  <template v-else>
    <section class="traffic-summary">
      <article>
        <span>{{ $t('portTraffic.periodTotal') }}</span>
        <strong>{{ bytes(summary?.current_period_total ?? null) }}</strong>
        <small>RX {{ bytes(summary?.current_period_rx ?? null) }} · TX {{ bytes(summary?.current_period_tx ?? null) }}</small>
      </article>
      <article>
        <span>{{ $t('portTraffic.quota') }}</span>
        <strong>{{ summary?.quota_percent == null ? $t('portTraffic.unlimited') : `${summary.quota_percent.toFixed(1)}%` }}</strong>
        <progress v-if="summary?.quota_percent != null" :value="Math.min(summary.quota_percent, 100)" max="100" />
        <small>{{ bytes(activePolicy.quota_bytes) }}</small>
      </article>
      <article>
        <span>{{ $t('portTraffic.runtime') }}</span>
        <strong>{{ summary?.runtime?.runtime_rule_state ?? activePolicy.status }}</strong>
        <small>{{ activePolicy.mode }} · {{ summary?.runtime?.shaping_state ?? 'disabled' }}</small>
        <small>
          {{ String(activePolicy.reset_policy.type ?? 'manual') }} ·
          {{ localTime(summary?.runtime?.next_reset_at ?? null) }}
        </small>
      </article>
      <article :class="{ warning: summary?.data_gap }">
        <span>{{ $t('portTraffic.lastSample') }}</span>
        <strong>{{ summary?.data_gap ? $t('portTraffic.dataGap') : $t('portTraffic.current') }}</strong>
        <small>{{ localTime(summary?.last_sample_at ?? null) }}</small>
      </article>
    </section>

    <section class="settings-section">
      <div class="section-heading">
        <div>
          <h2>{{ $t('portTraffic.recentEvents') }}</h2>
          <span>{{ $t('portTraffic.recentEventsHint') }}</span>
        </div>
      </div>
      <div v-if="summary?.recent_events.length" class="traffic-events">
        <article v-for="event in summary.recent_events" :key="event.id">
          <strong>{{ event.kind }} · {{ event.state }}</strong>
          <span>{{ event.summary }}</span>
          <small>{{ localTime(event.occurred_at) }}</small>
        </article>
      </div>
      <p v-else class="empty-panel">{{ $t('portTraffic.noEvents') }}</p>
    </section>

    <section v-if="summary?.data_gap" class="traffic-warning" role="status">
      <AlertTriangle :size="18" />
      <div><strong>{{ $t('portTraffic.gapTitle') }}</strong><p>{{ $t('portTraffic.gapDetail') }}</p></div>
    </section>

    <section class="settings-section">
      <div class="section-heading">
        <div>
          <h2>{{ $t('portTraffic.history') }}</h2>
          <span>{{ $t('portTraffic.historyHint', { resolution: history?.resolution ?? 'raw' }) }}</span>
        </div>
        <div v-if="canManage" class="traffic-actions">
          <button class="secondary-button" type="button" @click="openEdit">
            {{ $t('portTraffic.editPolicy') }}
          </button>
          <button class="secondary-button" type="button" @click="openChange">
            <ShieldCheck :size="15" />{{ $t('portTraffic.requestChange') }}
          </button>
          <button class="secondary-button" type="button" @click="openReset">
            <RotateCcw :size="15" />{{ $t('portTraffic.requestReset') }}
          </button>
        </div>
      </div>
      <div class="traffic-ranges" :aria-label="$t('portTraffic.range')">
        <button
          v-for="range in ['today', '1h', '24h', '7d', '30d', '90d'] as const"
          :key="range"
          class="secondary-button"
          :class="{ selected: historyRange === range }"
          type="button"
          @click="historyRange = range"
        >
          {{ $t(`portTraffic.range_${range}`) }}
        </button>
      </div>
      <div class="traffic-history" role="table">
        <div class="traffic-history-header" role="row">
          <span>{{ $t('portTraffic.time') }}</span><span>RX</span><span>TX</span><span>{{ $t('portTraffic.gaps') }}</span>
        </div>
        <div v-for="point in history?.points ?? []" :key="point.at" role="row" :class="{ discontinuity: point.discontinuity_count }">
          <span>{{ localTime(point.at) }}</span>
          <span>{{ bytes(point.rx_bytes) }}</span>
          <span>{{ bytes(point.tx_bytes) }}</span>
          <span>{{ point.discontinuity_reason || point.missing_intervals || '—' }}</span>
        </div>
        <p v-if="!history?.points.length">{{ $t('portTraffic.noHistory') }}</p>
      </div>
    </section>
  </template>

  <dialog ref="editDialog" class="modal-dialog">
    <form class="dialog-form" @submit.prevent="updatePolicy">
      <h2>{{ $t('portTraffic.editPolicy') }}</h2>
      <p v-if="activePolicy?.mode !== 'monitor_only'">{{ $t('portTraffic.editMonitorOnly') }}</p>
      <label><span>{{ $t('portTraffic.name') }}</span><input v-model="edit.name" required maxlength="120" /></label>
      <label>
        <span>{{ $t('portTraffic.quotaGiB') }}</span>
        <input v-model.number="edit.quota_gib" type="number" min="0" step="0.1" :disabled="activePolicy?.mode !== 'monitor_only'" />
      </label>
      <label class="traffic-checkbox">
        <input v-model="edit.enabled" type="checkbox" :disabled="activePolicy?.mode !== 'monitor_only'" />
        <span>{{ $t('portTraffic.enabled') }}</span>
      </label>
      <div class="dialog-actions">
        <button class="secondary-button" type="button" @click="editDialog?.close()">{{ $t('common.cancel') }}</button>
        <button class="primary-button" type="submit">{{ $t('common.submit') }}</button>
      </div>
    </form>
  </dialog>

  <dialog ref="createDialog" class="modal-dialog">
    <form class="dialog-form" @submit.prevent="createPolicy">
      <h2>{{ $t('portTraffic.addPolicy') }}</h2>
      <p>{{ $t('portTraffic.monitorOnlyDefault') }}</p>
      <label><span>{{ $t('portTraffic.name') }}</span><input v-model="newPolicy.name" required maxlength="120" /></label>
      <div class="form-grid">
        <label><span>{{ $t('portTraffic.protocol') }}</span><select v-model="newPolicy.protocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">{{ $t('common.all') }}</option></select></label>
        <label><span>{{ $t('portTraffic.direction') }}</span><select v-model="newPolicy.direction"><option value="rx">RX</option><option value="tx">TX</option><option value="both">RX + TX</option></select></label>
      </div>
      <div class="form-grid">
        <label><span>{{ $t('portTraffic.portStart') }}</span><input v-model.number="newPolicy.port_start" type="number" min="1" max="65535" required /></label>
        <label><span>{{ $t('portTraffic.portEnd') }}</span><input v-model.number="newPolicy.port_end" type="number" min="1" max="65535" required /></label>
      </div>
      <div class="form-grid">
        <label><span>{{ $t('portTraffic.interface') }}</span><input v-model="newPolicy.interface_name" maxlength="31" /></label>
        <label><span>{{ $t('portTraffic.quotaGiB') }}</span><input v-model.number="newPolicy.quota_gib" type="number" min="0" step="0.1" /></label>
      </div>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="createDialog?.close()">{{ $t('common.cancel') }}</button><button class="primary-button" type="submit">{{ $t('common.submit') }}</button></div>
    </form>
  </dialog>

  <dialog ref="changeDialog" class="modal-dialog">
    <form class="dialog-form" @submit.prevent="requestChange">
      <h2>{{ $t('portTraffic.requestChange') }}</h2>
      <p>{{ $t('portTraffic.approvalRequired') }}</p>
      <label><span>{{ $t('portTraffic.mode') }}</span><select v-model="change.mode"><option value="monitor_only">monitor_only</option><option value="enforcing">enforcing</option></select></label>
      <label><span>{{ $t('portTraffic.rateMbps') }}</span><input v-model.number="change.rate_mbps" type="number" min="0" step="0.1" /></label>
      <label>
        <span>{{ $t('portTraffic.resetType') }}</span>
        <select v-model="change.reset_type">
          <option value="manual">{{ $t('portTraffic.resetManual') }}</option>
          <option value="monthly">{{ $t('portTraffic.resetMonthly') }}</option>
          <option value="interval_days">{{ $t('portTraffic.resetEveryDays') }}</option>
          <option value="interval_months">{{ $t('portTraffic.resetEveryMonths') }}</option>
          <option value="yearly">{{ $t('portTraffic.resetYearly') }}</option>
          <option value="fixed_date">{{ $t('portTraffic.resetFixed') }}</option>
        </select>
      </label>
      <label v-if="change.reset_type !== 'manual'">
        <span>{{ $t('portTraffic.resetTimezone') }}</span>
        <input v-model="change.reset_timezone" required maxlength="64" />
      </label>
      <label v-if="['monthly', 'interval_months', 'yearly'].includes(change.reset_type)">
        <span>{{ $t('portTraffic.resetDay') }}</span>
        <input v-model.number="change.reset_day" type="number" min="1" max="31" required />
      </label>
      <label v-if="change.reset_type === 'yearly'">
        <span>{{ $t('portTraffic.resetMonth') }}</span>
        <input v-model.number="change.reset_month" type="number" min="1" max="12" required />
      </label>
      <label v-if="['interval_days', 'interval_months'].includes(change.reset_type)">
        <span>{{ $t('portTraffic.resetEvery') }}</span>
        <input v-model.number="change.reset_every" type="number" min="1" max="366" required />
      </label>
      <label v-if="['interval_days', 'interval_months'].includes(change.reset_type)">
        <span>{{ $t('portTraffic.resetAnchor') }}</span>
        <input v-model="change.reset_anchor" type="date" required />
      </label>
      <label v-if="change.reset_type === 'fixed_date'">
        <span>{{ $t('portTraffic.resetDate') }}</span>
        <input v-model="change.reset_date" type="date" required />
      </label>
      <label><span>{{ $t('portTraffic.reason') }}</span><textarea v-model="change.reason" required minlength="3" maxlength="500" /></label>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="changeDialog?.close()">{{ $t('common.cancel') }}</button><button class="primary-button" type="submit">{{ $t('portTraffic.sendApproval') }}</button></div>
    </form>
  </dialog>

  <dialog ref="resetDialog" class="modal-dialog">
    <form class="dialog-form" @submit.prevent="requestReset">
      <h2>{{ $t('portTraffic.requestReset') }}</h2>
      <p>{{ $t('portTraffic.resetWarning') }}</p>
      <label><span>{{ $t('portTraffic.reason') }}</span><textarea v-model="reset.reason" required minlength="3" maxlength="500" /></label>
      <label><span>{{ $t('portTraffic.confirmation') }}</span><input v-model="reset.confirmation" required /></label>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="resetDialog?.close()">{{ $t('common.cancel') }}</button><button class="primary-button" type="submit">{{ $t('portTraffic.sendApproval') }}</button></div>
    </form>
  </dialog>
</template>

<style scoped>
.traffic-toolbar,.traffic-summary{display:grid;gap:1rem;margin-bottom:1rem}.traffic-toolbar{grid-template-columns:repeat(2,minmax(0,1fr));padding:1rem;border:1px solid var(--border);border-radius:14px;background:var(--surface)}.traffic-toolbar label{display:grid;gap:.4rem}.traffic-summary{grid-template-columns:repeat(4,minmax(0,1fr))}.traffic-summary article{display:grid;gap:.45rem;padding:1rem;border:1px solid var(--border);border-radius:14px;background:var(--surface)}.traffic-summary strong{font-size:1.25rem}.traffic-summary small{color:var(--muted)}.traffic-summary .warning{border-color:var(--warning)}.traffic-warning,.traffic-notice{display:flex;gap:.7rem;align-items:flex-start;padding:.85rem 1rem;margin-bottom:1rem;border-radius:12px}.traffic-warning{background:color-mix(in srgb,var(--warning) 12%,transparent)}.traffic-warning p{margin:.2rem 0 0}.traffic-notice{background:color-mix(in srgb,var(--success) 12%,transparent)}.traffic-actions,.traffic-ranges{display:flex;gap:.5rem;flex-wrap:wrap}.traffic-ranges{margin-bottom:.75rem}.traffic-ranges .selected{border-color:var(--primary);color:var(--primary)}.traffic-checkbox{display:flex!important;align-items:center;gap:.6rem}.traffic-events{display:grid;gap:.65rem}.traffic-events article{display:grid;gap:.25rem;padding:.8rem;border:1px solid var(--border);border-radius:10px}.traffic-events small{color:var(--muted)}.traffic-history>div{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:1rem;padding:.7rem;border-bottom:1px solid var(--border)}.traffic-history-header{font-weight:700}.traffic-history .discontinuity{background:color-mix(in srgb,var(--warning) 9%,transparent)}.empty-panel{padding:3rem;text-align:center;color:var(--muted)}progress{width:100%}@media(max-width:900px){.traffic-summary{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:620px){.traffic-toolbar,.traffic-summary{grid-template-columns:1fr}.traffic-history{overflow:auto}.traffic-history>div{min-width:620px}}
</style>
