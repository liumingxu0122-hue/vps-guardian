<script setup lang="ts">
import { ShieldCheck, X } from '@lucide/vue'
import { nextTick, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { ApiError, jsonBody, request, setStepUpRequiredHandler } from '../api'
import { apiErrorKey } from '../i18n'

const { t } = useI18n()
const open = ref(false)
const password = ref('')
const totp = ref('')
const error = ref('')
const busy = ref(false)
const dialog = ref<HTMLElement | null>(null)
let returnFocus: HTMLElement | null = null

async function show(caught?: ApiError): Promise<void> {
  returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
  error.value = caught ? t(apiErrorKey(caught.status, caught.code)) : ''
  open.value = true
  await nextTick()
  dialog.value?.querySelector<HTMLInputElement>('input')?.focus()
}

function close(): void {
  open.value = false
  password.value = ''
  totp.value = ''
  error.value = ''
  void nextTick(() => returnFocus?.focus())
}

async function submit(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    await request('/api/v1/auth/step-up', {
      method: 'POST',
      ...jsonBody({ current_password: password.value, totp_code: totp.value.trim() || null }),
    })
    close()
  } catch (caught) {
    error.value = caught instanceof ApiError
      ? t(apiErrorKey(caught.status, caught.code), { status: caught.status, ...caught.params })
      : t('errors.network')
  } finally {
    busy.value = false
  }
}

function onKeydown(event: KeyboardEvent): void {
  if (!open.value) return
  if (event.key === 'Escape') {
    close()
    return
  }
  if (event.key !== 'Tab') return
  const focusable = [...(dialog.value?.querySelectorAll<HTMLElement>(
    'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
  ) ?? [])]
  if (!focusable.length) return
  const first = focusable[0]
  const last = focusable.at(-1)
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last?.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first?.focus()
  }
}

setStepUpRequiredHandler((error) => void show(error))
window.addEventListener('keydown', onKeydown)
onBeforeUnmount(() => {
  setStepUpRequiredHandler(() => undefined)
  window.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="rc6-step-up-backdrop" @mousedown.self="close">
      <section ref="dialog" class="rc6-step-up-dialog" role="dialog" aria-modal="true" aria-labelledby="rc6-step-up-title" aria-describedby="rc6-step-up-description">
        <header>
          <span class="rc5-resource-icon"><ShieldCheck :size="18" /></span>
          <div><h2 id="rc6-step-up-title">{{ t('accountSecurity.stepUp') }}</h2><p id="rc6-step-up-description">{{ t('accountSecurity.stepUpRetryHint') }}</p></div>
          <button class="icon-button" type="button" :aria-label="t('common.close')" @click="close"><X :size="17" /></button>
        </header>
        <form class="dialog-form" @submit.prevent="submit">
          <label><span>{{ t('accountSecurity.currentPassword') }}</span><input v-model="password" type="password" autocomplete="current-password" required minlength="12" /></label>
          <label><span>{{ t('accountSecurity.freshTotp') }}</span><input v-model="totp" inputmode="numeric" autocomplete="one-time-code" pattern="\d{6}" maxlength="6" /></label>
          <p v-if="error" class="form-error" role="alert">{{ error }}</p>
          <div class="dialog-actions">
            <button class="secondary-button" type="button" @click="close">{{ t('common.cancel') }}</button>
            <button class="primary-button" type="submit" :disabled="busy">{{ t('accountSecurity.confirmIdentity') }}</button>
          </div>
        </form>
      </section>
    </div>
  </Teleport>
</template>
