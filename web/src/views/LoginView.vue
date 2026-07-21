<script setup lang="ts">
import { Eye, EyeOff, LockKeyhole, ShieldCheck } from '@lucide/vue'
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '../api'
import { session } from '../session'

const email = ref('')
const password = ref('')
const totp = ref('')
const reveal = ref(false)
const loading = ref(false)
const error = ref('')
const route = useRoute()
const router = useRouter()

async function submit(): Promise<void> {
  error.value = ''
  loading.value = true
  try {
    await session.login(email.value.trim(), password.value, totp.value.trim())
    const target = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(target)
  } catch (caught) {
    error.value = caught instanceof ApiError ? caught.message : '无法连接控制器'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <main class="login-screen">
    <section class="login-panel" aria-labelledby="login-title">
      <div class="login-brand"><ShieldCheck :size="23" /><strong>VPS Guardian</strong></div>
      <header>
        <h1 id="login-title">登录控制中心</h1>
        <p>使用具有最小所需权限的运维账户</p>
      </header>
      <form @submit.prevent="submit">
        <label>
          <span>邮箱</span>
          <input v-model="email" type="email" autocomplete="username" required maxlength="255" />
        </label>
        <label>
          <span>密码</span>
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
            <button type="button" :aria-label="reveal ? '隐藏密码' : '显示密码'" @click="reveal = !reveal">
              <EyeOff v-if="reveal" :size="16" />
              <Eye v-else :size="16" />
            </button>
          </div>
        </label>
        <label>
          <span>TOTP 验证码</span>
          <input v-model="totp" inputmode="numeric" autocomplete="one-time-code" pattern="\d{6}" maxlength="6" />
        </label>
        <p v-if="error" class="form-error" role="alert">{{ error }}</p>
        <button class="primary-button login-button" type="submit" :disabled="loading">
          {{ loading ? '正在验证' : '登录' }}
        </button>
      </form>
    </section>
  </main>
</template>
