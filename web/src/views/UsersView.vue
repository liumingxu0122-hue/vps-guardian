<script setup lang="ts">
import { KeyRound, Monitor, Pencil, Plus, RefreshCw, ShieldCheck, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import DataTable from '../components/v3/DataTable.vue'
import { session } from '../session'
import type { User, UserSession } from '../types'
import { formatTime } from '../utils'

const users = ref<User[]>([])
const { locale } = useI18n()
const dialog = ref<HTMLDialogElement | null>(null)
const editDialog = ref<HTMLDialogElement | null>(null)
const passwordDialog = ref<HTMLDialogElement | null>(null)
const sessionsDialog = ref<HTMLDialogElement | null>(null)
const activeSessions = ref<UserSession[]>([])
const submitting = ref(false)
const form = ref({ email: '', password: '', role: 'viewer' as User['role'], scopes: '' })
const selected = ref<User | null>(null)
const editForm = ref({ role: 'viewer' as User['role'], is_active: true, scopes: '', current_password: '' })
const passwordForm = ref({ current_password: '', new_password: '' })
const isOwner = computed(() => session.user?.role === 'owner')
async function load(): Promise<void> {
  users.value = await request<User[]>('/api/v1/users')
}
async function createUser(): Promise<void> {
  submitting.value = true
  try {
    await request<User>('/api/v1/users', {
      method: 'POST',
      ...jsonBody({
        email: form.value.email,
        password: form.value.password,
        role: form.value.role,
        scopes: form.value.scopes.split(',').map((value) => value.trim()).filter(Boolean),
      }),
    })
    dialog.value?.close()
    form.value = { email: '', password: '', role: 'viewer', scopes: '' }
    await load()
  } finally {
    submitting.value = false
  }
}
async function revokeSessions(user: User): Promise<void> {
  await request<void>(`/api/v1/users/${user.id}/revoke-sessions`, { method: 'POST' })
}
async function openSessions(user: User): Promise<void> {
  selected.value = user
  activeSessions.value = await request<UserSession[]>(`/api/v1/users/${user.id}/sessions`)
  sessionsDialog.value?.showModal()
}
async function revokeSingleSession(sessionId: string): Promise<void> {
  if (!selected.value) return
  await request<void>(`/api/v1/users/${selected.value.id}/sessions/${sessionId}`, {
    method: 'DELETE',
  })
  activeSessions.value = await request<UserSession[]>(`/api/v1/users/${selected.value.id}/sessions`)
}
function openEdit(user: User): void {
  selected.value = user
  editForm.value = {
    role: user.role,
    is_active: user.is_active,
    scopes: user.scopes.join(', '),
    current_password: '',
  }
  editDialog.value?.showModal()
}
async function saveUser(): Promise<void> {
  if (!selected.value) return
  submitting.value = true
  try {
    await request<User>(`/api/v1/users/${selected.value.id}`, {
      method: 'PATCH',
      ...jsonBody({
        role: editForm.value.role,
        is_active: editForm.value.is_active,
        scopes: editForm.value.scopes.split(',').map((value) => value.trim()).filter(Boolean),
        current_password: editForm.value.current_password,
      }),
    })
    editDialog.value?.close()
    await load()
  } finally {
    submitting.value = false
  }
}
function openPassword(user: User): void {
  selected.value = user
  passwordForm.value = { current_password: '', new_password: '' }
  passwordDialog.value?.showModal()
}
async function rotatePassword(): Promise<void> {
  if (!selected.value) return
  submitting.value = true
  try {
    await request<void>(`/api/v1/users/${selected.value.id}/rotate-password`, {
      method: 'POST',
      ...jsonBody({
        ...passwordForm.value,
        confirmation: 'ROTATE USER CREDENTIAL',
      }),
    })
    passwordDialog.value?.close()
  } finally {
    submitting.value = false
  }
}
onMounted(load)
</script>

<template>
  <PageHeader :title="$t('users.title')" :description="$t('users.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :aria-label="$t('common.refresh')" @click="load"><RefreshCw :size="17" /></button>
      <button v-if="isOwner" class="primary-button" type="button" @click="dialog?.showModal()"><Plus :size="15" />{{ $t('users.add') }}</button>
    </template>
  </PageHeader>
  <DataTable :label="$t('users.title')" :empty="!users.length">
    <template #head><tr><th>{{ $t('users.account') }}</th><th>{{ $t('users.role') }}</th><th>TOTP</th><th>{{ $t('users.lastLogin') }}</th><th>{{ $t('common.actions') }}</th></tr></template>
    <tr v-for="user in users" :key="user.id">
      <td :data-label="locale === 'zh-CN' ? '账户' : 'Account'"><span><strong>{{ user.email }}</strong><small>{{ user.scopes.length ? (locale === 'zh-CN' ? `${user.scopes.length} 项权限` : `${user.scopes.length} scopes`) : $t('users.roleDefault') }}</small></span></td>
      <td :data-label="locale === 'zh-CN' ? '角色' : 'Role'"><StatusBadge :status="user.is_active ? user.role : 'disabled'" /></td>
      <td data-label="TOTP"><span><ShieldCheck :size="14" />{{ user.totp_enabled ? $t('common.enabled') : $t('common.disabled') }}</span></td>
      <td :data-label="locale === 'zh-CN' ? '最近登录' : 'Last login'"><span>{{ formatTime(user.last_login_at) }}</span></td>
      <td :data-label="locale === 'zh-CN' ? '操作' : 'Actions'"><span class="row-actions">
        <button v-if="isOwner" class="icon-button bordered" type="button" :aria-label="$t('users.manage')" @click="openEdit(user)"><Pencil :size="14" /></button>
        <button v-if="isOwner" class="icon-button bordered" type="button" :aria-label="$t('users.rotatePassword')" @click="openPassword(user)"><KeyRound :size="14" /></button>
        <button class="icon-button bordered" type="button" :aria-label="$t('users.viewSessions')" @click="openSessions(user)"><Monitor :size="14" /></button>
        <button class="secondary-button" type="button" @click="revokeSessions(user)">{{ $t('users.revokeSessions') }}</button>
      </span></td>
    </tr>
  </DataTable>
  <dialog ref="dialog" class="modal-dialog compact">
    <form method="dialog" class="dialog-header"><div><h2>{{ $t('users.add') }}</h2><p>{{ $t('users.ownerOnly') }}</p></div><button class="icon-button"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="createUser">
      <label><span>{{ $t('users.email') }}</span><input v-model="form.email" type="email" required /></label>
      <label><span>{{ $t('login.password') }}</span><input v-model="form.password" type="password" minlength="14" required /></label>
      <label><span>{{ $t('users.role') }}</span><select v-model="form.role"><option value="viewer">{{ $t('status.viewer') }}</option><option value="auditor">{{ $t('status.auditor') }}</option><option value="operator">{{ $t('status.operator') }}</option><option value="admin">{{ $t('status.admin') }}</option><option value="owner">{{ $t('status.owner') }}</option></select></label>
      <label><span>{{ $t('users.scopes') }}</span><input v-model="form.scopes" placeholder="hosts:read, alerts:read" /></label>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">{{ $t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="submitting">{{ $t('users.create') }}</button></div>
    </form>
  </dialog>
  <dialog ref="editDialog" class="modal-dialog compact">
    <form method="dialog" class="dialog-header"><div><h2>{{ $t('users.manage') }}</h2><p>{{ selected?.email }}</p></div><button class="icon-button"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="saveUser">
      <label><span>{{ $t('users.role') }}</span><select v-model="editForm.role"><option value="viewer">{{ $t('status.viewer') }}</option><option value="auditor">{{ $t('status.auditor') }}</option><option value="operator">{{ $t('status.operator') }}</option><option value="admin">{{ $t('status.admin') }}</option><option value="owner">{{ $t('status.owner') }}</option></select></label>
      <label class="toggle-line"><input v-model="editForm.is_active" type="checkbox" /><span>{{ $t('users.activeAccount') }}</span></label>
      <label><span>{{ $t('users.scopes') }}</span><input v-model="editForm.scopes" /></label>
      <label><span>{{ $t('users.currentPassword') }}</span><input v-model="editForm.current_password" type="password" minlength="12" required /></label>
      <p class="permission-note">{{ $t('users.lastOwnerGuard') }}</p>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="editDialog?.close()">{{ $t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="submitting">{{ $t('common.submit') }}</button></div>
    </form>
  </dialog>
  <dialog ref="passwordDialog" class="modal-dialog compact">
    <form method="dialog" class="dialog-header"><div><h2>{{ $t('users.rotatePassword') }}</h2><p>{{ selected?.email }}</p></div><button class="icon-button"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="rotatePassword">
      <label><span>{{ $t('users.currentPassword') }}</span><input v-model="passwordForm.current_password" type="password" minlength="12" required /></label>
      <label><span>{{ $t('users.newPassword') }}</span><input v-model="passwordForm.new_password" type="password" minlength="14" required /></label>
      <p class="permission-note">{{ $t('users.rotationWarning') }}</p>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="passwordDialog?.close()">{{ $t('common.cancel') }}</button><button class="danger-button" type="submit" :disabled="submitting">{{ $t('users.rotatePassword') }}</button></div>
    </form>
  </dialog>
  <dialog ref="sessionsDialog" class="modal-dialog compact">
    <form method="dialog" class="dialog-header"><div><h2>{{ $t('users.activeSessions') }}</h2><p>{{ selected?.email }}</p></div><button class="icon-button" :aria-label="$t('common.close')"><X :size="18" /></button></form>
    <div class="dialog-form">
      <p class="permission-note">{{ $t('users.sessionsHint') }}</p>
      <div v-for="row in activeSessions" :key="row.id" class="session-row">
        <span><strong>{{ row.device_name || (row.current ? $t('accountSecurity.current') : $t('accountSecurity.other')) }}</strong><small>{{ formatTime(row.last_seen_at) }} → {{ formatTime(row.absolute_expires_at) }}</small></span>
        <button class="danger-button" type="button" @click="revokeSingleSession(row.id)">{{ $t('users.revoke') }}</button>
      </div>
      <p v-if="!activeSessions.length">{{ $t('users.noActiveSessions') }}</p>
    </div>
  </dialog>
</template>
