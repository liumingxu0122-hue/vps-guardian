<script setup lang="ts">
import { Eye, EyeOff, LockKeyhole, ShieldCheck } from '@lucide/vue'
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { ApiError } from '../api'
import { apiErrorKey, setLocale, type SupportedLocale } from '../i18n'
import { session } from '../session'

const email = ref('')
const password = ref('')
const totp = ref('')
const reveal = ref(false)
const loading = ref(false)
const error = ref('')
const route = useRoute()
const router = useRouter()
const { locale, t } = useI18n()

async function submit(): Promise<void> {
  error.value = ''
  loading.value = true
  try {
    await session.login(email.value.trim(), password.value, totp.value.trim())
    const target = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(target)
  } catch (caught) {
    error.value = caught instanceof ApiError ? t(apiErrorKey(caught.status), { status: caught.status }) : t('errors.network')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <main class="login-screen">
    <label class="login-language language-select"><span class="sr-only">{{ t('locale.select') }}</span><select :value="locale" :aria-label="t('locale.select')" @change="setLocale(($event.target as HTMLSelectElement).value as SupportedLocale)"><option value="en-US">English</option><option value="zh-CN">简体中文</option></select></label>
    <section class="login-panel" aria-labelledby="login-title">
      <div class="login-brand"><ShieldCheck :size="23" /><strong>VPS Guardian</strong></div>
      <header>
        <h1 id="login-title">{{ t('login.title') }}</h1>
        <p>{{ t('login.description') }}</p>
      </header>
      <form @submit.prevent="submit">
        <label>
          <span>{{ t('login.email') }}</span>
          <input v-model="email" type="email" autocomplete="username" required maxlength="255" />
        </label>
        <label>
          <span>{{ t('login.password') }}</span>
          <div class="password-field">
            <LockKeyhole :size="16" aria-hidden="true" />
            <input
              v-model="password"
              :type="reveal ? 'text' : 'password'"
              autocomplete="current-password"
              required
              minlength="12"
              maxlength="256"
            />
            <button type="button" :aria-label="reveal ? t('login.hidePassword') : t('login.showPassword')" @click="reveal = !reveal">
              <EyeOff v-if="reveal" :size="16" />
              <Eye v-else :size="16" />
            </button>
          </div>
        </label>
        <label>
          <span>{{ t('login.totp') }}</span>
          <input v-model="totp" inputmode="numeric" autocomplete="one-time-code" pattern="\d{6}" maxlength="6" />
        </label>
        <p v-if="error" class="form-error" role="alert">{{ error }}</p>
        <button class="primary-button login-button" type="submit" :disabled="loading">
          {{ loading ? t('login.submitting') : t('login.submit') }}
        </button>
      </form>
    </section>
  </main>
</template>
