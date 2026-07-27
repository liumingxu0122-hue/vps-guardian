<script setup lang="ts">
import {
  ArrowLeft,
  Check,
  ChevronDown,
  Clock3,
  Copy,
  Eye,
  FileCheck2,
  Filter,
  Maximize2,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
} from '@lucide/vue'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'

import { jsonBody, request } from '../api'
import { filterApprovalSummaries, shouldLoadApprovalEvidence } from '../approvalPresentation'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { session } from '../session'
import type {
  ApprovalDetail,
  ApprovalEvidence,
  ApprovalStatus,
  ApprovalSummary,
} from '../types'
import { formatTime, titleize } from '../utils'

type Decision =
  | 'approved'
  | 'approved_with_conditions'
  | 'changes_requested'
  | 'rejected'
  | 'dry_run_only'

const { t, te } = useI18n()
const route = useRoute()
const router = useRouter()
const approvals = ref<ApprovalSummary[]>([])
const selected = ref<ApprovalDetail | null>(null)
const evidence = ref<ApprovalEvidence | null>(null)
const loading = ref(true)
const detailLoading = ref(false)
const listError = ref('')
const query = ref('')
const statusFilter = ref<ApprovalStatus | 'all'>('all')
const riskFilter = ref<number | 'all'>('all')
const mineOnly = ref(false)
const decisionDialog = ref<HTMLDialogElement | null>(null)
const decisionBar = ref<HTMLElement | null>(null)
const decisionBarArmed = ref(false)
const decision = ref<Decision>('dry_run_only')
const confirmation = ref('')
const currentPassword = ref('')
const rollbackConfirmed = ref(false)
const submitting = ref(false)
const decisionError = ref('')
const evidenceLoading = ref(false)
const evidenceSearch = ref('')
const evidenceDialog = ref<HTMLDialogElement | null>(null)
let detailController: AbortController | null = null

const canDecide = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const canReadEvidence = computed(() => canDecide.value)
const selectedId = computed(() => String(route.query.approval ?? ''))
const pendingCount = computed(() => approvals.value.filter((item) => item.status === 'pending').length)
const expiringCount = computed(() => {
  const now = Date.now()
  return approvals.value.filter((item) => item.status === 'pending'
    && new Date(item.expires_at).getTime() - now <= 60 * 60 * 1000).length
})
const approvedWaitingCount = computed(() => approvals.value.filter((item) =>
  ['approved', 'approved_with_conditions'].includes(item.status) && item.execution_status !== 'completed').length)
const failedCount = computed(() => approvals.value.filter((item) => item.status === 'failed'
  || item.execution_status === 'failed').length)
const completedWeekCount = computed(() => {
  const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
  return approvals.value.filter((item) => item.status === 'executed'
    && new Date(item.requested_at).getTime() >= weekAgo).length
})
const compactMode = ref(typeof window !== 'undefined' && window.matchMedia('(max-width: 900px)').matches)
const filtered = computed(() => {
  const items = filterApprovalSummaries(
    approvals.value,
    query.value,
    statusFilter.value,
    riskFilter.value,
  )
  if (!mineOnly.value) return items
  const currentLabel = session.user?.email?.split('@')[0] ?? ''
  return items.filter((item) => item.requester?.label === currentLabel)
})
const evidenceText = computed(() => evidence.value ? JSON.stringify(evidence.value, null, 2) : '')
const evidenceLines = computed(() => {
  const needle = evidenceSearch.value.trim().toLocaleLowerCase()
  return evidenceText.value.split('\n').map((text, index) => ({ number: index + 1, text }))
    .filter((line) => !needle || line.text.toLocaleLowerCase().includes(needle))
})

function actionLabel(value: string): string {
  const key = `approvals.actions.${value}`
  return te(key) ? t(key) : titleize(value)
}

function statusLabel(value: string): string {
  const key = `status.${value}`
  return te(key) ? t(key) : titleize(value)
}

function riskLabel(level: number): string {
  return t(`approvals.riskLevels.${Math.min(Math.max(level, 0), 3)}`)
}

function targetLabel(item: ApprovalSummary): string {
  return [item.target.host, item.target.service].filter(Boolean).join(' · ') || t('approvals.unknownTarget')
}

async function loadList(): Promise<void> {
  loading.value = true
  listError.value = ''
  try {
    approvals.value = await request<ApprovalSummary[]>('/api/v1/approvals/presentation?limit=100')
    const requested = selectedId.value
    const initial = approvals.value.find((item) => item.id === requested)
      ?? (compactMode.value ? undefined : approvals.value[0])
    if (initial && initial.id !== selected.value?.id) await selectApproval(initial.id, false)
  } catch {
    listError.value = t('approvals.loadFailed')
  } finally {
    loading.value = false
  }
}

async function selectApproval(id: string, updateUrl = true): Promise<void> {
  detailController?.abort()
  detailController = new AbortController()
  detailLoading.value = true
  evidence.value = null
  if (updateUrl) {
    await router.replace({ query: { ...route.query, approval: id } })
  }
  try {
    selected.value = await request<ApprovalDetail>(`/api/v1/approvals/${id}/presentation`, {
      signal: detailController.signal,
      dedupe: false,
    })
    decisionBarArmed.value = false
    await nextTick()
    updateDecisionBar()
  } catch (caught) {
    if (caught instanceof DOMException && caught.name === 'AbortError') return
    listError.value = t('approvals.loadFailed')
  } finally {
    detailLoading.value = false
  }
}

function closeMobileDetail(): void {
  selected.value = null
  void router.replace({ query: { ...route.query, approval: undefined } })
}

function openDecision(value: Decision): void {
  decision.value = value
  confirmation.value = ''
  currentPassword.value = ''
  rollbackConfirmed.value = false
  decisionError.value = ''
  decisionDialog.value?.showModal()
}

async function submitDecision(): Promise<void> {
  if (!selected.value) return
  submitting.value = true
  decisionError.value = ''
  try {
    await request(`/api/v1/approvals/${selected.value.id}/decision`, {
      method: 'POST',
      ...jsonBody({
        decision: decision.value,
        confirmation: confirmation.value,
        current_password: currentPassword.value || null,
        rollback_confirmed: rollbackConfirmed.value,
      }),
    })
    decisionDialog.value?.close()
    await loadList()
  } catch {
    decisionError.value = t('approvals.failed')
  } finally {
    submitting.value = false
  }
}

async function loadEvidence(event: Event): Promise<void> {
  const details = event.currentTarget as HTMLDetailsElement
  if (
    !selected.value
    || !shouldLoadApprovalEvidence(details.open, Boolean(evidence.value), canReadEvidence.value)
  ) return
  evidenceLoading.value = true
  try {
    evidence.value = await request<ApprovalEvidence>(
      `/api/v1/approvals/${selected.value.id}/evidence`,
    )
  } finally {
    evidenceLoading.value = false
  }
}

async function copyEvidence(): Promise<void> {
  if (evidenceText.value) await navigator.clipboard.writeText(evidenceText.value)
}

function updateDecisionBar(): void {
  if (decisionBarArmed.value || !decisionBar.value) return
  if (decisionBar.value.getBoundingClientRect().top <= window.innerHeight - 12) {
    decisionBarArmed.value = true
  }
}

watch(selectedId, (id) => {
  if (id && id !== selected.value?.id && approvals.value.some((item) => item.id === id)) {
    void selectApproval(id, false)
  }
})
onMounted(() => {
  window.addEventListener('scroll', updateDecisionBar, { passive: true })
  window.addEventListener('resize', updateDecisionBar, { passive: true })
  void loadList()
})
onBeforeUnmount(() => {
  detailController?.abort()
  window.removeEventListener('scroll', updateDecisionBar)
  window.removeEventListener('resize', updateDecisionBar)
})
</script>

<template>
  <PageHeader :title="t('approvals.title')" :description="t('approvals.description')" />

  <section class="approval-summary-strip" :aria-label="t('approvals.summary')">
    <div><strong>{{ pendingCount }}</strong><span>{{ t('approvals.pending') }}</span></div>
    <div><strong>{{ expiringCount }}</strong><span>{{ t('approvals.expiringSoon') }}</span></div>
    <div><strong>{{ approvedWaitingCount }}</strong><span>{{ t('approvals.awaitingExecution') }}</span></div>
    <div><strong>{{ failedCount }}</strong><span>{{ t('approvals.recentFailures') }}</span></div>
    <div><strong>{{ completedWeekCount }}</strong><span>{{ t('approvals.completedWeek') }}</span></div>
  </section>

  <div class="approval-toolbar">
    <label class="approval-search">
      <Search :size="15" />
      <span class="sr-only">{{ t('approvals.search') }}</span>
      <input v-model="query" type="search" :placeholder="t('approvals.searchPlaceholder')" />
    </label>
    <label class="approval-filter">
      <Filter :size="14" />
      <span class="sr-only">{{ t('approvals.statusFilter') }}</span>
      <select v-model="statusFilter">
        <option value="all">{{ t('approvals.allStatuses') }}</option>
        <option value="pending">{{ statusLabel('pending') }}</option>
        <option value="approved">{{ statusLabel('approved') }}</option>
        <option value="rejected">{{ statusLabel('rejected') }}</option>
        <option value="executed">{{ statusLabel('executed') }}</option>
        <option value="expired">{{ statusLabel('expired') }}</option>
      </select>
    </label>
    <label class="approval-filter">
      <ShieldAlert :size="14" />
      <span class="sr-only">{{ t('approvals.riskFilter') }}</span>
      <select v-model="riskFilter">
        <option value="all">{{ t('approvals.allRisks') }}</option>
        <option v-for="level in [0, 1, 2, 3]" :key="level" :value="level">
          {{ riskLabel(level) }}
        </option>
      </select>
    </label>
    <button type="button" class="approval-toolbar-button" :class="{ active: mineOnly }" @click="mineOnly = !mineOnly">
      {{ t('approvals.myRequests') }}
    </button>
    <button type="button" class="approval-toolbar-button" :aria-label="t('common.refresh')" @click="loadList">
      <RefreshCw :size="14" />{{ t('common.refresh') }}
    </button>
  </div>

  <p v-if="listError" class="approval-error" role="alert">{{ listError }}</p>
  <div v-if="loading" class="approval-loading" aria-live="polite">{{ t('common.loading') }}</div>
  <div
    v-else-if="filtered.length"
    class="approval-workspace"
    :class="{ 'detail-open': selected }"
  >
    <section class="approval-queue" role="listbox" tabindex="0" :aria-label="t('approvals.queue')">
      <button
        v-for="approval in filtered"
        :key="approval.id"
        type="button"
        role="option"
        class="approval-row"
        :class="{ selected: selected?.id === approval.id }"
        :aria-selected="selected?.id === approval.id"
        @click="selectApproval(approval.id)"
      >
        <span class="approval-row-main">
          <span class="approval-row-title">{{ actionLabel(approval.action_name) }}</span>
          <span class="approval-row-target">{{ targetLabel(approval) }}</span>
        </span>
        <span class="approval-row-meta">
          <span class="risk-pill" :data-level="approval.risk_level">{{ riskLabel(approval.risk_level) }}</span>
          <StatusBadge :status="approval.status" />
        </span>
        <span class="approval-row-foot">
          <span>{{ approval.requester?.label || t('approvals.systemRequester') }}</span>
          <time :datetime="approval.requested_at">{{ formatTime(approval.requested_at) }}</time>
        </span>
      </button>
    </section>

    <article v-if="selected" class="approval-product-detail" :aria-busy="detailLoading">
      <button class="approval-back" type="button" @click="closeMobileDetail">
        <ArrowLeft :size="16" />{{ t('approvals.backToQueue') }}
      </button>
      <header class="approval-product-header">
        <div>
          <span class="approval-eyebrow">{{ t('approvals.requestLabel') }}</span>
          <h2>{{ actionLabel(selected.action_name) }}</h2>
          <p>{{ targetLabel(selected) }}</p>
        </div>
        <StatusBadge :status="selected.status" />
      </header>

      <section class="approval-decision-context">
        <div class="approval-risk-callout" :data-level="selected.risk_level">
          <ShieldAlert :size="20" />
          <div>
            <strong>{{ riskLabel(selected.risk_level) }}</strong>
            <span>{{ t(`approvals.riskReasons.${selected.risk_reason}`, selected.risk_reason) }}</span>
          </div>
        </div>
        <dl class="approval-facts">
          <div><dt>{{ t('approvals.requester') }}</dt><dd>{{ selected.requester?.label || t('approvals.systemRequester') }}</dd></div>
          <div><dt>{{ t('approvals.approver') }}</dt><dd>{{ selected.approver?.label || t('approvals.notDecided') }}</dd></div>
          <div><dt>{{ t('approvals.expires') }}</dt><dd>{{ formatTime(selected.expires_at) }}</dd></div>
          <div><dt>{{ t('approvals.execution') }}</dt><dd>{{ statusLabel(selected.execution_status || selected.progress_label) }}</dd></div>
        </dl>
      </section>

      <section class="approval-section">
        <h3>{{ t('approvals.impact') }}</h3>
        <div v-if="selected.impact_facts.length" class="impact-fact-grid">
          <div v-for="fact in selected.impact_facts" :key="fact.key">
            <span>{{ t(`approvals.factKeys.${fact.key}`, titleize(fact.key)) }}</span>
            <strong>{{ fact.value }}</strong>
          </div>
        </div>
        <p v-else class="approval-empty-copy">{{ t('approvals.noStructuredImpact') }}</p>
      </section>

      <section class="approval-section">
        <h3>{{ t('approvals.executionSteps') }}</h3>
        <ol v-if="selected.steps.length" class="approval-steps">
          <li v-for="step in selected.steps" :key="step.order">
            <span>{{ step.order }}</span>
            <div><strong>{{ actionLabel(step.action) }}</strong><small>{{ step.target || t('approvals.managedTarget') }}</small></div>
            <em v-if="step.dry_run">{{ t('approvals.dryRun') }}</em>
          </li>
        </ol>
        <p v-else class="approval-empty-copy">{{ t('approvals.noStructuredSteps') }}</p>
      </section>

      <section v-if="selected.dry_run_available" class="approval-section approval-dry-run">
        <h3>{{ t('approvals.dryRunAvailable') }}</h3>
        <p>{{ selected.dry_run_status ? statusLabel(selected.dry_run_status) : t('approvals.dryRunPreview') }}</p>
        <button
          v-if="selected.status === 'pending' && canDecide"
          type="button"
          class="secondary-button"
          @click="openDecision('dry_run_only')"
        ><Eye :size="15" />{{ t('approvals.runDryRun') }}</button>
      </section>

      <section class="approval-section approval-recovery">
        <h3>{{ t('approvals.rollback') }}</h3>
        <div class="recovery-card">
          <FileCheck2 :size="19" />
          <div>
            <strong>{{ selected.rollback_available ? t('approvals.rollbackReady') : t('approvals.noRecovery') }}</strong>
            <span>{{ selected.recovery_point_label || t('approvals.noRecoveryReference') }}</span>
          </div>
        </div>
        <ol v-if="selected.rollback_steps.length" class="rollback-list">
          <li v-for="step in selected.rollback_steps" :key="step">{{ step }}</li>
        </ol>
      </section>

      <section class="approval-section">
        <h3>{{ t('approvals.timeline') }}</h3>
        <ol class="approval-timeline">
          <li v-for="entry in selected.timeline" :key="`${entry.at}-${entry.event}`">
            <Clock3 :size="14" />
            <div><strong>{{ statusLabel(entry.event) }}</strong><span>{{ entry.actor || t('approvals.systemRequester') }}</span></div>
            <time :datetime="entry.at">{{ formatTime(entry.at) }}</time>
          </li>
        </ol>
      </section>

      <details
        v-if="selected.raw_evidence_available && canReadEvidence"
        class="approval-evidence"
        @toggle="loadEvidence"
      >
        <summary><span>{{ t('approvals.rawEvidence') }}</span><ChevronDown :size="16" /></summary>
        <p>{{ t('approvals.evidenceScope') }}</p>
        <div v-if="evidenceLoading">{{ t('common.loading') }}</div>
        <div v-else-if="evidence" class="approval-evidence-viewer">
          <div class="approval-evidence-toolbar">
            <label><Search :size="14" /><span class="sr-only">{{ t('approvals.searchEvidence') }}</span><input v-model="evidenceSearch" type="search" :placeholder="t('approvals.searchEvidence')" /></label>
            <button type="button" @click="copyEvidence"><Copy :size="14" />{{ t('common.copy') }}</button>
            <button type="button" @click="evidenceDialog?.showModal()"><Maximize2 :size="14" />{{ t('approvals.fullscreen') }}</button>
          </div>
          <ol class="approval-evidence-lines">
            <li v-for="line in evidenceLines" :key="line.number"><span>{{ line.number }}</span><code>{{ line.text || ' ' }}</code></li>
          </ol>
        </div>
      </details>

      <div
        v-if="selected.status === 'pending' && canDecide"
        ref="decisionBar"
        class="approval-decision-bar"
        :class="{ armed: decisionBarArmed }"
      >
        <div>
          <strong>{{ t('approvals.decisionBar') }}</strong>
          <span>{{ t('approvals.decisionHint') }}</span>
        </div>
        <div>
          <button type="button" class="secondary-button" @click="openDecision('changes_requested')">{{ t('approvals.requestChanges') }}</button>
          <button type="button" class="secondary-button" @click="openDecision('rejected')"><X :size="15" />{{ t('approvals.reject') }}</button>
          <button v-if="selected.dry_run_available" type="button" class="secondary-button" @click="openDecision('dry_run_only')"><Eye :size="15" />{{ t('approvals.dryRun') }}</button>
          <button type="button" class="secondary-button" @click="openDecision('approved_with_conditions')">{{ t('approvals.conditionalApprove') }}</button>
          <button type="button" class="primary-button" @click="openDecision('approved')"><Check :size="15" />{{ t('approvals.approve') }}</button>
        </div>
      </div>
    </article>
  </div>
  <EmptyState v-else-if="!loading" :title="t('approvals.noItems')" />

  <dialog ref="decisionDialog" class="modal-dialog compact">
    <form method="dialog" class="dialog-header">
      <div><h2>{{ t('approvals.dialogTitle') }}</h2><p>{{ statusLabel(decision) }}</p></div>
      <button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button>
    </form>
    <form class="dialog-form" @submit.prevent="submitDecision">
      <label>
        <span>{{ t('approvals.confirmation') }}</span>
        <textarea v-model="confirmation" required minlength="3" maxlength="255"></textarea>
      </label>
      <template v-if="selected && selected.risk_level >= 2 && ['approved', 'approved_with_conditions'].includes(decision)">
        <label>
          <span>{{ t('approvals.reauthenticate') }}</span>
          <input v-model="currentPassword" type="password" required minlength="12" autocomplete="current-password" />
        </label>
        <label class="decision-check">
          <input v-model="rollbackConfirmed" type="checkbox" required />
          <span>{{ t('approvals.rollbackChecked') }}</span>
        </label>
      </template>
      <p v-if="decision === 'approved'" class="decision-warning"><ShieldAlert :size="16" />{{ t('approvals.approvalWarning') }}</p>
      <p v-if="decisionError" class="form-error" role="alert">{{ decisionError }}</p>
      <div class="dialog-actions">
        <button class="secondary-button" type="button" @click="decisionDialog?.close()">{{ t('common.cancel') }}</button>
        <button class="primary-button" type="submit" :disabled="submitting">{{ t('approvals.submit') }}</button>
      </div>
    </form>
  </dialog>

  <dialog ref="evidenceDialog" class="approval-evidence-dialog">
    <form method="dialog" class="dialog-header">
      <div><h2>{{ t('approvals.rawEvidence') }}</h2><p>{{ t('approvals.evidenceScope') }}</p></div>
      <button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button>
    </form>
    <div class="approval-evidence-viewer fullscreen">
      <div class="approval-evidence-toolbar">
        <label><Search :size="14" /><span class="sr-only">{{ t('approvals.searchEvidence') }}</span><input v-model="evidenceSearch" type="search" :placeholder="t('approvals.searchEvidence')" /></label>
        <button type="button" @click="copyEvidence"><Copy :size="14" />{{ t('common.copy') }}</button>
      </div>
      <ol class="approval-evidence-lines">
        <li v-for="line in evidenceLines" :key="line.number"><span>{{ line.number }}</span><code>{{ line.text || ' ' }}</code></li>
      </ol>
    </div>
  </dialog>
</template>
