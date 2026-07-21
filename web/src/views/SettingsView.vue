<script setup lang="ts">
import { Check, LockKeyhole, RefreshCw, ShieldCheck, X } from '@lucide/vue'
import { onMounted, ref } from 'vue'

import { request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import type { PublicSettings } from '../types'
import { formatBytes, titleize } from '../utils'

const settings = ref<PublicSettings | null>(null)
async function load(): Promise<void> { settings.value = await request<PublicSettings>('/api/v1/settings/public') }
onMounted(load)
</script>

<template>
  <PageHeader title="系统设置" description="控制器运行模式与不含 Secret 的安全配置">
    <template #actions><button class="icon-button bordered" type="button" title="刷新" aria-label="刷新设置" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div v-if="settings" class="settings-layout">
    <section class="settings-section">
      <div class="section-heading"><div><h2>运行参数</h2><span>只读有效配置</span></div><span class="environment-badge">{{ settings.environment }}</span></div>
      <dl class="settings-list">
        <div><dt>安全 Cookie</dt><dd><Check v-if="settings.secure_cookies" :size="16" /><X v-else :size="16" />{{ settings.secure_cookies ? '启用' : '关闭' }}</dd></div>
        <div><dt>自动创建数据库结构</dt><dd>{{ settings.auto_create_schema ? '启用' : '关闭' }}</dd></div>
        <div><dt>事故日志上限</dt><dd>{{ formatBytes(settings.max_incident_log_bytes) }}</dd></div>
        <div><dt>十分钟登录尝试</dt><dd>{{ settings.login_attempts_per_10m }} 次</dd></div>
        <div><dt>Nonce 有效期</dt><dd>{{ settings.nonce_ttl_seconds }} 秒</dd></div>
        <div><dt>允许来源</dt><dd class="mono wrap">{{ settings.allowed_origins.join(', ') }}</dd></div>
      </dl>
    </section>
    <section class="settings-section">
      <div class="section-heading"><div><h2>安全边界</h2><span>服务端强制执行</span></div><ShieldCheck :size="19" /></div>
      <div class="feature-grid">
        <div v-for="(enabled, name) in settings.features" :key="name" :class="{ disabled: !enabled }"><span><LockKeyhole :size="16" />{{ titleize(String(name)) }}</span><strong>{{ enabled ? '启用' : '禁用' }}</strong></div>
      </div>
    </section>
  </div>
</template>
