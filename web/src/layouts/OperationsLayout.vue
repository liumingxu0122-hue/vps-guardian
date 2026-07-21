<script setup lang="ts">
import {
  Activity,
  ArchiveRestore,
  BellRing,
  BookOpenCheck,
  Boxes,
  ChevronRight,
  ClipboardCheck,
  FileClock,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Server,
  Settings,
  ShieldCheck,
  Sun,
  Wrench,
  X,
} from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { setLocale, type SupportedLocale } from '../i18n'
import { session } from '../session'

const route = useRoute()
const router = useRouter()
const { locale, t } = useI18n()
const mobileOpen = ref(false)
const theme = ref<'light' | 'dark'>('dark')
const roleOrder = { viewer: 0, operator: 1, admin: 2, owner: 3 }
const navItems = [
  { to: '/overview', label: 'nav.overview', icon: LayoutDashboard, exact: true },
  { to: '/hosts', label: 'nav.hosts', icon: Server },
  { to: '/services', label: 'nav.services', icon: Boxes },
  { to: '/alerts', label: 'nav.alerts', icon: BellRing },
  { to: '/incidents', label: 'nav.incidents', icon: BellRing },
  { to: '/repairs', label: 'nav.repairs', icon: Wrench },
  { to: '/recovery', label: 'nav.recovery', icon: ArchiveRestore, minimumRole: 'operator' },
  { to: '/approvals', label: 'nav.approvals', icon: ClipboardCheck, minimumRole: 'operator' },
  { to: '/audit', label: 'nav.audit', icon: FileClock, minimumRole: 'admin' },
  { to: '/settings', label: 'nav.settings', icon: Settings, minimumRole: 'admin' },
] as const

const visibleItems = computed(() =>
  navItems.filter(
    (item) =>
      !('minimumRole' in item) ||
      roleOrder[session.user?.role ?? 'viewer'] >= roleOrder[item.minimumRole],
  ),
)

function active(to: string, exact?: boolean): boolean {
  return exact ? route.path === to : route.path.startsWith(to)
}

function applyTheme(value: 'light' | 'dark'): void {
  theme.value = value
  document.documentElement.dataset.theme = value
  document.documentElement.style.colorScheme = value
  localStorage.setItem('guardian_theme', value)
}

function toggleTheme(): void {
  applyTheme(theme.value === 'dark' ? 'light' : 'dark')
}

function changeLocale(event: Event): void {
  setLocale((event.target as HTMLSelectElement).value as SupportedLocale)
}

onMounted(() => {
  const saved = localStorage.getItem('guardian_theme')
  applyTheme(
    saved === 'light' || saved === 'dark'
      ? saved
      : window.matchMedia('(prefers-color-scheme: light)').matches
        ? 'light'
        : 'dark',
  )
})

async function logout(): Promise<void> {
  await session.logout()
  await router.push('/login')
}
</script>

<template>
  <div class="operations-shell">
    <button class="mobile-menu icon-button" type="button" :aria-label="t('nav.open')" @click="mobileOpen = true">
      <Menu :size="20" />
    </button>
    <div v-if="mobileOpen" class="nav-scrim" @click="mobileOpen = false"></div>
    <aside class="sidebar" :class="{ open: mobileOpen }">
      <div class="brand-row">
        <div class="brand-mark"><ShieldCheck :size="20" /></div>
        <div><strong>VPS Guardian</strong><span>{{ t('nav.controlCenter') }}</span></div>
        <button class="close-nav icon-button" type="button" :aria-label="t('nav.close')" @click="mobileOpen = false">
          <X :size="19" />
        </button>
      </div>
      <div class="controller-state">
        <Activity :size="16" />
        <div><span>{{ t('nav.currentSession') }}</span><strong>{{ t('nav.authenticated') }}</strong></div>
        <span class="live-dot"></span>
      </div>
      <nav class="primary-nav" :aria-label="t('nav.main')">
        <RouterLink
          v-for="item in visibleItems"
          :key="item.to"
          :to="item.to"
          :class="{ active: active(item.to, 'exact' in item && item.exact) }"
          @click="mobileOpen = false"
        >
          <component :is="item.icon" :size="17" />
          <span>{{ t(item.label) }}</span>
          <ChevronRight v-if="active(item.to, 'exact' in item && item.exact)" :size="14" />
        </RouterLink>
      </nav>
      <div class="sidebar-footer">
        <label class="language-select">
          <span class="sr-only">{{ t('locale.select') }}</span>
          <select :value="locale" :aria-label="t('locale.select')" @change="changeLocale">
            <option value="en-US">English</option><option value="zh-CN">简体中文</option>
          </select>
        </label>
        <button class="theme-toggle" type="button" :aria-label="theme === 'dark' ? t('nav.switchLight') : t('nav.switchDark')" @click="toggleTheme">
          <Sun v-if="theme === 'dark'" :size="16" /><Moon v-else :size="16" />
          <span>{{ theme === 'dark' ? t('nav.light') : t('nav.dark') }}</span>
        </button>
        <a href="/docs" target="_blank" rel="noreferrer"><BookOpenCheck :size="16" />{{ t('nav.apiDocs') }}</a>
        <div class="user-row">
          <div class="user-avatar">{{ session.user?.email.slice(0, 1).toUpperCase() }}</div>
          <div><strong>{{ session.user?.email }}</strong><span>{{ session.user?.role }}</span></div>
          <button class="icon-button" type="button" :title="t('nav.logout')" :aria-label="t('nav.logout')" @click="logout">
            <LogOut :size="17" />
          </button>
        </div>
      </div>
    </aside>
    <main class="main-surface">
      <RouterView />
    </main>
  </div>
</template>
