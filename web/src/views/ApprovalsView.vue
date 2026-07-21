<script setup lang="ts">
import { Check, Eye, FileCheck2, ShieldAlert, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { session } from '../session'
import type { Approval } from '../types'
import { formatTime, titleize } from '../utils'

const approvals = ref<Approval[]>([])
const selected = ref<Approval | null>(null)
const decisionDialog = ref<HTMLDialogElement | null>(null)
const decision = ref<'approved' | 'rejected' | 'dry_run_only'>('dry_run_only')
const confirmation = ref('')
const submitting = ref(false)
const error = ref('')
const canDecide = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))

async function load(): Promise<void> {
  approvals.value = await request<Approval[]>('/api/v1/approvals')
  selected.value = selected.value
    ? approvals.value.find((item) => item.id === selected.value?.id) ?? null
    : approvals.value[0] ?? null
}

function openDecision(value: typeof decision.value): void {
  decision.value = value
  confirmation.value = ''
  error.value = ''
  decisionDialog.value?.showModal()
}

async function submitDecision(): Promise<void> {
  if (!selected.value) return
  submitting.value = true
  error.value = ''
  try {
    await request<Approval>(`/api/v1/approvals/${selected.value.id}/decision`, {
      method: 'POST',
      ...jsonBody({ decision: decision.value, confirmation: confirmation.value }),
    })
    decisionDialog.value?.close()
    await load()
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : '审批失败'
  } finally {
    submitting.value = false
  }
}

onMounted(load)
</script>

<template>
  <PageHeader title="审批中心" description="高风险动作的影响、恢复点与回滚方式" />
  <div v-if="approvals.length" class="approval-layout">
    <section class="approval-list">
      <button v-for="approval in approvals" :key="approval.id" type="button" :class="{ selected: selected?.id === approval.id }" @click="selected = approval">
        <span class="risk-level">L{{ approval.risk_level }}</span>
        <span><strong>{{ titleize(approval.action_name) }}</strong><small>{{ formatTime(approval.requested_at) }}</small></span>
        <StatusBadge :status="approval.status" />
      </button>
    </section>
    <section v-if="selected" class="approval-detail">
      <header><div><span class="mono">{{ selected.id }}</span><h2>{{ titleize(selected.action_name) }}</h2></div><StatusBadge :status="selected.status" /></header>
      <div class="risk-banner"><ShieldAlert :size="20" /><div><strong>风险等级 {{ selected.risk_level }}</strong><span>事故 {{ selected.incident_id }}</span></div></div>
      <div class="approval-columns">
        <section><h3>动作参数</h3><dl class="key-values"><div v-for="(value, key) in selected.parameters" :key="key"><dt>{{ titleize(String(key)) }}</dt><dd>{{ String(value) }}</dd></div></dl></section>
        <section><h3>影响范围</h3><dl class="key-values"><div v-for="(value, key) in selected.impact" :key="key"><dt>{{ titleize(String(key)) }}</dt><dd>{{ String(value) }}</dd></div></dl></section>
      </div>
      <section><h3>恢复与回滚</h3><div class="recovery-reference"><FileCheck2 :size="18" /><div><strong>{{ selected.recovery_point_id || '未指定恢复点' }}</strong><span>{{ selected.rollback_plan.join(' · ') || '没有可用回滚计划' }}</span></div></div></section>
      <div v-if="selected.status === 'pending' && canDecide" class="approval-actions">
        <button class="secondary-button" type="button" @click="openDecision('rejected')"><X :size="16" />拒绝</button>
        <button class="secondary-button warning" type="button" @click="openDecision('dry_run_only')"><Eye :size="16" />仅 Dry-run</button>
        <button class="danger-button" type="button" @click="openDecision('approved')"><Check :size="16" />批准执行</button>
      </div>
    </section>
  </div>
  <EmptyState v-else title="没有审批请求" />
  <dialog ref="decisionDialog" class="modal-dialog compact">
    <form method="dialog" class="dialog-header"><div><h2>确认审批决定</h2><p>{{ titleize(decision) }}</p></div><button class="icon-button" aria-label="关闭"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="submitDecision">
      <label><span>二次确认说明</span><textarea v-model="confirmation" required minlength="3" maxlength="255"></textarea></label>
      <p v-if="error" class="form-error">{{ error }}</p>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="decisionDialog?.close()">取消</button><button class="primary-button" type="submit" :disabled="submitting">提交决定</button></div>
    </form>
  </dialog>
</template>
