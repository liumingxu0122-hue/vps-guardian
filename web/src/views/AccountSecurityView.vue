<script setup lang="ts">
import { Copy, KeyRound, RefreshCw, ShieldCheck, Trash2 } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { ApiError, jsonBody, request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import DataTable from '../components/v3/DataTable.vue'
import { apiErrorKey } from '../i18n'
import {
  auditActionLabel,
  resultLabel,
  sessionDeviceLabel,
  sessionNetworkLabel,
  sessionSignInMethodLabel,
} from '../presentationRegistry'
import { session } from '../session'
import type { AuditEntry, RecoveryCodeStatus, UserSession } from '../types'
import { formatTime, relativeTime } from '../utils'

interface RecoveryBatch {
  codes: string[]
  remaining: number
}

interface StepUpResponse {
  step_up_until: string
}

const router = useRouter()
const { locale, t } = useI18n()
const sessions = ref<UserSession[]>([])
const status = ref<RecoveryCodeStatus | null>(null)
const events = ref<AuditEntry[]>([])
const currentPassword = ref('')
const totpCode = ref('')
const recoveryCodes = ref<string[]>([])
const saved = ref(false)
const busy = ref(false)
const error = ref('')
const stepUpUntil = ref<string | null>(null)
const deviceName = ref('')
const currentSession = computed(() => sessions.value.find((row) => row.current) ?? null)

function setError(caught: unknown): void {
  error.value = caught instanceof ApiError
    ? t(apiErrorKey(caught.status, caught.code), { status: caught.status, ...caught.params })
    : t('errors.network')
}

async function load(): Promise<void> {
  error.value = ''
  try {
    ;[sessions.value, status.value, events.value] = await Promise.all([
      request<UserSession[]>('/api/v1/auth/sessions'),
      request<RecoveryCodeStatus>('/api/v1/auth/recovery-codes'),
      request<AuditEntry[]>('/api/v1/auth/security-events'),
    ])
    stepUpUntil.value = currentSession.value?.step_up_until ?? stepUpUntil.value
    deviceName.value = currentSession.value?.device_name ?? ''
  } catch (caught) {
    setError(caught)
  }
}

async function stepUp(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    const result = await request<StepUpResponse>('/api/v1/auth/step-up', {
      method: 'POST',
      ...jsonBody({ current_password: currentPassword.value, totp_code: totpCode.value.trim() || null }),
    })
    stepUpUntil.value = result.step_up_until
    await load()
  } catch (caught) {
    setError(caught)
  } finally {
    busy.value = false
  }
}

async function revoke(sessionId: string): Promise<void> {
  error.value = ''
  try {
    await request(`/api/v1/auth/sessions/${sessionId}`, { method: 'DELETE' })
    await load()
  } catch (caught) {
    setError(caught)
  }
}

async function revokeOthers(): Promise<void> {
  if (!window.confirm(t('accountSecurity.revokeOthersConfirm'))) return
  error.value = ''
  try {
    await request('/api/v1/auth/sessions/revoke-others', { method: 'POST' })
    await load()
  } catch (caught) {
    setError(caught)
  }
}

async function renameCurrent(): Promise<void> {
  if (!deviceName.value.trim()) return
  error.value = ''
  try {
    await request('/api/v1/auth/sessions/current', {
      method: 'PATCH',
      ...jsonBody({ device_name: deviceName.value.trim() }),
    })
    await load()
  } catch (caught) {
    setError(caught)
  }
}

async function regenerate(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    const payload = await request<RecoveryBatch>('/api/v1/auth/recovery-codes/regenerate', {
      method: 'POST',
      ...jsonBody({ current_password: currentPassword.value, totp_code: totpCode.value.trim() }),
    })
    recoveryCodes.value = payload.codes
    saved.value = false
    currentPassword.value = ''
    totpCode.value = ''
  } catch (caught) {
    setError(caught)
  } finally {
    busy.value = false
  }
}

async function confirmSaved(): Promise<void> {
  if (!saved.value) return
  try {
    await request('/api/v1/auth/recovery-codes/confirm', {
      method: 'POST',
      ...jsonBody({ confirmation: 'I SAVED MY RECOVERY CODES' }),
    })
    recoveryCodes.value = []
    await session.refreshUser()
    await load()
  } catch (caught) {
    setError(caught)
  }
}

async function copyCodes(): Promise<void> {
  await navigator.clipboard.writeText(recoveryCodes.value.join('\n'))
}

async function disableTotp(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    await request('/api/v1/auth/totp/disable', {
      method: 'POST',
      ...jsonBody({ current_password: currentPassword.value, totp_code: totpCode.value.trim() }),
    })
  } catch (caught) {
    setError(caught)
    busy.value = false
    return
  }
  try {
    await session.logout()
  } catch {
    // The security mutation already revoked the current session.
  }
  await router.replace('/login')
  busy.value = false
}

onMounted(load)
</script>

<template>
  <PageHeader :title="t('accountSecurity.title')" :description="t('accountSecurity.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :aria-label="t('accountSecurity.refresh')" @click="load">
        <RefreshCw :size="17" />
      </button>
    </template>
  </PageHeader>

  <p v-if="error" class="form-error" role="alert">{{ error }}</p>

  <section class="settings-section">
    <div class="section-heading">
      <div><h2>{{ t('accountSecurity.stepUp') }}</h2><span>{{ t('accountSecurity.stepUpHint') }}</span></div>
    </div>
    <div class="dialog-form rc6-step-up">
      <p v-if="stepUpUntil && new Date(stepUpUntil) > new Date()" class="permission-note" role="status">
        {{ t('accountSecurity.confirmedUntil', { time: formatTime(stepUpUntil) }) }}
      </p>
      <label><span>{{ t('accountSecurity.currentPassword') }}</span><input v-model="currentPassword" type="password" autocomplete="current-password" minlength="12" /></label>
      <label><span>{{ t('accountSecurity.freshTotp') }}</span><input v-model="totpCode" inputmode="numeric" autocomplete="one-time-code" pattern="\d{6}" maxlength="6" /></label>
      <button class="primary-button" type="button" :disabled="busy || !currentPassword" @click="stepUp">
        <ShieldCheck :size="15" />{{ t('accountSecurity.confirmIdentity') }}
      </button>
    </div>
  </section>

  <section class="settings-section">
    <div class="section-heading">
      <div><h2>{{ t('accountSecurity.activeSessions') }}</h2><span>{{ t('accountSecurity.activeSessionsHint') }}</span></div>
      <button v-if="sessions.some((row) => !row.current)" class="secondary-button" type="button" @click="revokeOthers">
        {{ t('accountSecurity.revokeOthers') }}
      </button>
    </div>
    <div v-if="currentSession" class="rc6-device-name">
      <label><span>{{ t('accountSecurity.rename') }}</span><input v-model="deviceName" maxlength="120" /></label>
      <button class="secondary-button" type="button" :disabled="!deviceName.trim()" @click="renameCurrent">{{ t('accountSecurity.renameSave') }}</button>
    </div>
    <DataTable :label="t('accountSecurity.activeSessions')" :empty="!sessions.length" :total="sessions.length" density="compact">
      <template #head><tr><th>{{ t('accountSecurity.session') }}</th><th>{{ t('accountSecurity.lastSeen') }}</th><th>{{ t('accountSecurity.idleExpiry') }}</th><th>{{ t('accountSecurity.absoluteExpiry') }}</th><th>{{ t('accountSecurity.action') }}</th></tr></template>
      <tr v-for="row in sessions" :key="row.id">
        <td :data-label="t('accountSecurity.session')">
          <span class="rc5-resource rc6-session-summary"><span class="rc5-resource-icon"><ShieldCheck :size="16" /></span><span><strong>{{ row.device_name || (row.current ? t('accountSecurity.current') : t('accountSecurity.other')) }}</strong><small><span>{{ sessionDeviceLabel(row.user_agent_summary, locale) }}</span><span>{{ sessionNetworkLabel(row.ip_summary, locale) }}</span><span>{{ sessionSignInMethodLabel(row.created_via, locale) }}</span><span>{{ row.remember_me ? t('accountSecurity.remembered') : t('accountSecurity.standard') }}</span></small></span></span>
        </td>
        <td :data-label="t('accountSecurity.lastSeen')">{{ relativeTime(row.last_seen_at) }}</td>
        <td :data-label="t('accountSecurity.idleExpiry')">{{ formatTime(row.idle_expires_at) }}</td>
        <td :data-label="t('accountSecurity.absoluteExpiry')">{{ formatTime(row.absolute_expires_at) }}</td>
        <td :data-label="t('accountSecurity.action')"><button v-if="!row.current" class="icon-button bordered" type="button" :aria-label="t('accountSecurity.revoke')" @click="revoke(row.id)"><Trash2 :size="14" /></button><span v-else>{{ t('accountSecurity.current') }}</span></td>
      </tr>
    </DataTable>
  </section>

  <section class="settings-section">
    <div class="section-heading"><div><h2>{{ t('accountSecurity.recoveryCodes') }}</h2><span>{{ t(status?.low ? 'accountSecurity.remainingLow' : 'accountSecurity.remaining', { count: status?.remaining ?? 0 }) }}</span></div></div>
    <div class="dialog-form">
      <template v-if="recoveryCodes.length">
        <p class="permission-note">{{ t('accountSecurity.shownOnce') }}</p>
        <div class="recovery-code-grid"><code v-for="code in recoveryCodes" :key="code">{{ code }}</code></div>
        <button class="secondary-button" type="button" @click="copyCodes"><Copy :size="15" />{{ t('accountSecurity.copyCodes') }}</button>
        <label class="toggle-line"><input v-model="saved" type="checkbox" /><span>{{ t('accountSecurity.savedOffline') }}</span></label>
        <button class="primary-button" type="button" :disabled="!saved" @click="confirmSaved">{{ t('accountSecurity.confirmSaved') }}</button>
      </template>
      <template v-else>
        <div class="dialog-actions">
          <button class="secondary-button" type="button" :disabled="busy" @click="regenerate"><KeyRound :size="15" />{{ t('accountSecurity.regenerate') }}</button>
          <button class="danger-button" type="button" :disabled="busy" @click="disableTotp">{{ t('accountSecurity.disableTotp') }}</button>
        </div>
      </template>
    </div>
  </section>

  <section class="settings-section">
    <div class="section-heading"><div><h2>{{ t('accountSecurity.identityEvents') }}</h2><span>{{ t('accountSecurity.identityEventsHint') }}</span></div></div>
    <DataTable :label="t('accountSecurity.identityEvents')" :empty="!events.length" :total="events.length" density="compact">
      <template #head><tr><th>{{ t('accountSecurity.event') }}</th><th>{{ t('accountSecurity.result') }}</th><th>{{ t('accountSecurity.time') }}</th></tr></template>
      <tr v-for="event in events" :key="event.id">
        <td :data-label="t('accountSecurity.event')"><span class="rc5-resource"><span class="rc5-resource-icon"><ShieldCheck :size="16" /></span><strong>{{ auditActionLabel(event.action, t('common.unknown'), locale) }}</strong></span></td>
        <td :data-label="t('accountSecurity.result')">{{ resultLabel(event.outcome, locale) }}</td><td :data-label="t('accountSecurity.time')">{{ formatTime(event.created_at) }}</td>
      </tr>
    </DataTable>
  </section>
</template>
