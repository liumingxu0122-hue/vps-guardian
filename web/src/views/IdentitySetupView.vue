<script setup lang="ts">
import { Check, Copy, KeyRound, ShieldCheck } from '@lucide/vue'
import { computed, onBeforeUnmount, ref } from 'vue'
import { useRouter } from 'vue-router'

import { jsonBody, request } from '../api'
import { session } from '../session'

interface LoginResponse {
  access_token: string
  csrf_token: string
  identity_setup_required: boolean
  recovery_codes_remaining: number | null
}

interface TotpSetup {
  secret: string
  provisioning_uri: string
  displayed_once: true
}

interface RecoveryBatch {
  codes: string[]
  remaining: number
  displayed_once: true
}

const router = useRouter()
const currentPassword = ref('')
const newPassword = ref('')
const totpCode = ref('')
const secret = ref('')
const provisioningUri = ref('')
const recoveryCodes = ref<string[]>([])
const saved = ref(false)
const copied = ref(false)
const busy = ref(false)
const error = ref('')
const needsPassword = computed(() => session.user?.must_change_password ?? true)
const needsTotp = computed(() => !(session.user?.totp_enabled ?? false))

async function changePassword(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    const payload = await request<LoginResponse>('/api/v1/auth/change-password', {
      method: 'POST',
      ...jsonBody({
        current_password: currentPassword.value,
        new_password: newPassword.value,
        retain_current_session: true,
      }),
    })
    await session.replaceCredentials(payload)
    currentPassword.value = newPassword.value
    newPassword.value = ''
  } catch {
    error.value = 'Password change failed. Check the current password and strength policy.'
  } finally {
    busy.value = false
  }
}

async function beginTotp(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    const payload = await request<TotpSetup>('/api/v1/auth/totp/setup', {
      method: 'POST',
      ...jsonBody({ current_password: currentPassword.value }),
    })
    secret.value = payload.secret
    provisioningUri.value = payload.provisioning_uri
  } catch {
    error.value = 'TOTP setup could not be started. Re-enter your current password.'
  } finally {
    busy.value = false
  }
}

async function enableTotp(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    const payload = await request<RecoveryBatch>('/api/v1/auth/totp/enable', {
      method: 'POST',
      ...jsonBody({
        current_password: currentPassword.value,
        totp_code: totpCode.value.trim(),
      }),
    })
    recoveryCodes.value = payload.codes
    secret.value = ''
    provisioningUri.value = ''
    totpCode.value = ''
    await session.refreshUser()
  } catch {
    error.value = 'The TOTP code was invalid or the setup window expired.'
  } finally {
    busy.value = false
  }
}

async function regenerateCodes(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    const payload = await request<RecoveryBatch>('/api/v1/auth/recovery-codes/regenerate', {
      method: 'POST',
      ...jsonBody({
        current_password: currentPassword.value,
        totp_code: totpCode.value.trim(),
      }),
    })
    recoveryCodes.value = payload.codes
    totpCode.value = ''
  } catch {
    error.value = 'Recovery-code regeneration requires the current password and a fresh TOTP code.'
  } finally {
    busy.value = false
  }
}

async function copyCodes(): Promise<void> {
  await navigator.clipboard.writeText(recoveryCodes.value.join('\n'))
  copied.value = true
  window.setTimeout(() => {
    copied.value = false
  }, 1500)
}

async function confirmSaved(): Promise<void> {
  if (!saved.value || recoveryCodes.value.length === 0) return
  busy.value = true
  error.value = ''
  try {
    await request('/api/v1/auth/recovery-codes/confirm', {
      method: 'POST',
      ...jsonBody({ confirmation: 'I SAVED MY RECOVERY CODES' }),
    })
    recoveryCodes.value = []
    await session.refreshUser()
    await router.replace('/overview')
  } catch {
    error.value = 'Confirmation failed. Keep this page open and try again.'
  } finally {
    busy.value = false
  }
}

onBeforeUnmount(() => {
  secret.value = ''
  provisioningUri.value = ''
  recoveryCodes.value = []
})
</script>

<template>
  <main class="login-screen identity-setup-screen">
    <section class="login-panel identity-setup-panel" aria-labelledby="identity-setup-title">
      <div class="login-brand"><ShieldCheck :size="23" /><strong>VPS Guardian</strong></div>
      <header>
        <h1 id="identity-setup-title">Complete identity recovery setup</h1>
        <p>Administrative access stays blocked until password, TOTP, and recovery-code steps are complete.</p>
      </header>

      <form v-if="needsPassword" class="dialog-form" @submit.prevent="changePassword">
        <h2><KeyRound :size="18" /> 1. Replace the initial password</h2>
        <label><span>Initial password</span><input v-model="currentPassword" type="password" autocomplete="current-password" required minlength="12" /></label>
        <label><span>New passphrase</span><input v-model="newPassword" type="password" autocomplete="new-password" required minlength="14" /></label>
        <button class="primary-button" type="submit" :disabled="busy">Change password</button>
      </form>

      <section v-else-if="needsTotp" class="dialog-form">
        <h2><ShieldCheck :size="18" /> 2. Enable TOTP</h2>
        <label><span>Current password</span><input v-model="currentPassword" type="password" autocomplete="current-password" required minlength="12" /></label>
        <button v-if="!secret" class="primary-button" type="button" :disabled="busy" @click="beginTotp">Generate one-time setup secret</button>
        <template v-else>
          <p class="permission-note">This secret is shown once. It is kept only in this page's memory and is cleared when you leave.</p>
          <code class="one-time-secret">{{ secret }}</code>
          <small>{{ provisioningUri }}</small>
          <label><span>First valid TOTP code</span><input v-model="totpCode" inputmode="numeric" autocomplete="one-time-code" pattern="\d{6}" maxlength="6" required /></label>
          <button class="primary-button" type="button" :disabled="busy" @click="enableTotp">Verify and enable</button>
        </template>
      </section>

      <section v-else class="dialog-form">
        <h2><KeyRound :size="18" /> 3. Save recovery codes</h2>
        <template v-if="recoveryCodes.length">
          <p class="permission-note">These codes cannot be retrieved again. Store them offline; never paste them into support, URLs, or analytics.</p>
          <div class="recovery-code-grid"><code v-for="code in recoveryCodes" :key="code">{{ code }}</code></div>
          <button class="secondary-button" type="button" @click="copyCodes"><Check v-if="copied" :size="15" /><Copy v-else :size="15" />{{ copied ? 'Copied' : 'Copy codes' }}</button>
          <label class="toggle-line"><input v-model="saved" type="checkbox" /><span>I saved these recovery codes in a secure offline location.</span></label>
          <button class="primary-button" type="button" :disabled="busy || !saved" @click="confirmSaved">Finish identity setup</button>
        </template>
        <template v-else>
          <p class="permission-note">The previous one-time display is unavailable. Regenerate a new batch; the old batch will be revoked.</p>
          <label><span>Current password</span><input v-model="currentPassword" type="password" autocomplete="current-password" required minlength="12" /></label>
          <label><span>Fresh TOTP code</span><input v-model="totpCode" inputmode="numeric" autocomplete="one-time-code" pattern="\d{6}" maxlength="6" required /></label>
          <button class="primary-button" type="button" :disabled="busy" @click="regenerateCodes">Regenerate recovery codes</button>
        </template>
      </section>
      <p v-if="error" class="form-error" role="alert">{{ error }}</p>
    </section>
  </main>
</template>
