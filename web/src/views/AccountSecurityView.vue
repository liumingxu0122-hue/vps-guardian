<script setup lang="ts">
import { Copy, KeyRound, RefreshCw, ShieldCheck, Trash2 } from '@lucide/vue'
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import DataTable from '../components/v3/DataTable.vue'
import { auditActionLabel, resultLabel } from '../presentationRegistry'
import { session } from '../session'
import type { AuditEntry, RecoveryCodeStatus, UserSession } from '../types'
import { formatTime } from '../utils'

interface RecoveryBatch {
  codes: string[]
  remaining: number
}

const router = useRouter()
const { locale } = useI18n()
const sessions = ref<UserSession[]>([])
const status = ref<RecoveryCodeStatus | null>(null)
const events = ref<AuditEntry[]>([])
const currentPassword = ref('')
const totpCode = ref('')
const recoveryCodes = ref<string[]>([])
const saved = ref(false)
const busy = ref(false)

async function load(): Promise<void> {
  ;[sessions.value, status.value, events.value] = await Promise.all([
    request<UserSession[]>('/api/v1/auth/sessions'),
    request<RecoveryCodeStatus>('/api/v1/auth/recovery-codes'),
    request<AuditEntry[]>('/api/v1/auth/security-events'),
  ])
}

async function revoke(sessionId: string): Promise<void> {
  await request(`/api/v1/auth/sessions/${sessionId}`, { method: 'DELETE' })
  await load()
}

async function regenerate(): Promise<void> {
  busy.value = true
  try {
    const payload = await request<RecoveryBatch>('/api/v1/auth/recovery-codes/regenerate', {
      method: 'POST',
      ...jsonBody({
        current_password: currentPassword.value,
        totp_code: totpCode.value.trim(),
      }),
    })
    recoveryCodes.value = payload.codes
    saved.value = false
    totpCode.value = ''
  } finally {
    busy.value = false
  }
}

async function confirmSaved(): Promise<void> {
  if (!saved.value) return
  await request('/api/v1/auth/recovery-codes/confirm', {
    method: 'POST',
    ...jsonBody({ confirmation: 'I SAVED MY RECOVERY CODES' }),
  })
  recoveryCodes.value = []
  currentPassword.value = ''
  await session.refreshUser()
  await load()
}

async function copyCodes(): Promise<void> {
  await navigator.clipboard.writeText(recoveryCodes.value.join('\n'))
}

async function disableTotp(): Promise<void> {
  busy.value = true
  try {
    await request('/api/v1/auth/totp/disable', {
      method: 'POST',
      ...jsonBody({
        current_password: currentPassword.value,
        totp_code: totpCode.value.trim(),
      }),
    })
  } finally {
    try {
      await session.logout()
    } catch {
      // The server has already revoked this session.
    }
    await router.replace('/login')
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <PageHeader title="Account security" description="Your server-side sessions, recovery codes, and recent identity events">
    <template #actions><button class="icon-button bordered" type="button" aria-label="Refresh" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>

  <section class="settings-section">
    <div class="section-heading"><div><h2>Active sessions</h2><span>IP and browser values are keyed digests, not raw identifiers.</span></div></div>
    <DataTable label="Active sessions" :empty="!sessions.length" :total="sessions.length" density="compact">
      <template #head><tr><th>Session</th><th>Issued</th><th>Expires</th><th>Action</th></tr></template>
      <tr v-for="row in sessions" :key="row.id">
        <td><span class="rc5-resource"><span class="rc5-resource-icon"><ShieldCheck :size="16" /></span><strong>{{ row.current ? 'Current session' : 'Other signed-in session' }}</strong></span></td>
        <td>{{ formatTime(row.issued_at) }}</td><td>{{ formatTime(row.expires_at) }}</td>
        <td><button v-if="!row.current" class="icon-button bordered" type="button" aria-label="Revoke session" @click="revoke(row.id)"><Trash2 :size="14" /></button><span v-else>Current</span></td>
      </tr>
    </DataTable>
  </section>

  <section class="settings-section">
    <div class="section-heading"><div><h2>Recovery codes</h2><span>{{ status?.remaining ?? 0 }} unused codes remain<span v-if="status?.low"> — regenerate soon</span>.</span></div></div>
    <div class="dialog-form">
      <template v-if="recoveryCodes.length">
        <p class="permission-note">This new batch is shown once. Regeneration revoked every older unused code.</p>
        <div class="recovery-code-grid"><code v-for="code in recoveryCodes" :key="code">{{ code }}</code></div>
        <button class="secondary-button" type="button" @click="copyCodes"><Copy :size="15" />Copy codes</button>
        <label class="toggle-line"><input v-model="saved" type="checkbox" /><span>I saved the codes offline.</span></label>
        <button class="primary-button" type="button" :disabled="!saved" @click="confirmSaved">Confirm saved</button>
      </template>
      <template v-else>
        <label><span>Current password</span><input v-model="currentPassword" type="password" autocomplete="current-password" minlength="12" /></label>
        <label><span>Fresh TOTP code</span><input v-model="totpCode" inputmode="numeric" autocomplete="one-time-code" pattern="\d{6}" maxlength="6" /></label>
        <div class="dialog-actions">
          <button class="secondary-button" type="button" :disabled="busy" @click="regenerate"><KeyRound :size="15" />Regenerate codes</button>
          <button class="danger-button" type="button" :disabled="busy" @click="disableTotp">Disable TOTP and sign out</button>
        </div>
      </template>
    </div>
  </section>

  <section class="settings-section">
    <div class="section-heading"><div><h2>Recent identity events</h2><span>Passwords, tokens, TOTP secrets, and recovery codes are excluded.</span></div></div>
    <DataTable label="Recent identity events" :empty="!events.length" :total="events.length" density="compact">
      <template #head><tr><th>Event</th><th>Result</th><th>Time</th></tr></template>
      <tr v-for="event in events" :key="event.id">
        <td><span class="rc5-resource"><span class="rc5-resource-icon"><ShieldCheck :size="16" /></span><strong>{{ auditActionLabel(event.action, 'Unknown audit action', locale) }}</strong></span></td>
        <td>{{ resultLabel(event.outcome, locale) }}</td><td>{{ formatTime(event.created_at) }}</td>
      </tr>
    </DataTable>
  </section>
</template>
