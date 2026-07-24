<script setup lang="ts">
import {
  Activity,
  ArchiveRestore,
  BellRing,
  BookOpenCheck,
  Boxes,
  ChevronLeft,
  ChevronRight,
  ClipboardCheck,
  FileClock,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Sun,
  Users,
  Wrench,
  X,
} from '@lucide/vue'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { setLocale, type SupportedLocale } from '../i18n'
import { session } from '../session'

const route = useRoute()
const router = useRouter()
const { locale, t } = useI18n()
const mobileOpen = ref(false)
const collapsed = ref(localStorage.getItem('guardian_nav_collapsed') === 'true')
const paletteOpen = ref(false)
const paletteQuery = ref('')
const theme = ref<'light' | 'dark'>('dark')
const roleOrder = { viewer: 0, operator: 1, admin: 2, owner: 3 }
const navGroups = [
  {
    label: 'nav.groupOverview',
    items: [
      { to: '/overview', label: 'nav.overview', icon: LayoutDashboard, exact: true },
      { to: '/attention', label: 'nav.attention', icon: Activity },
    ],
  },
  {
    label: 'nav.groupInfrastructure',
    items: [
      { to: '/hosts', label: 'nav.hosts', icon: Server },
      { to: '/services', label: 'nav.services', icon: Boxes },
      { to: '/topology', label: 'nav.topology', icon: Network },
    ],
  },
  {
    label: 'nav.groupResponse',
    items: [
      { to: '/alerts', label: 'nav.alerts', icon: BellRing },
      { to: '/incidents', label: 'nav.incidents', icon: BellRing },
      { to: '/repairs', label: 'nav.repairs', icon: Wrench },
      { to: '/approvals', label: 'nav.approvals', icon: ClipboardCheck, minimumRole: 'operator' },
    ],
  },
  {
    label: 'nav.groupProtection',
    items: [
      { to: '/recovery', label: 'nav.recovery', icon: ArchiveRestore, minimumRole: 'operator' },
    ],
  },
  {
    label: 'nav.groupAdministration',
    items: [
      { to: '/security', label: 'nav.security', icon: ShieldCheck, minimumRole: 'admin' },
      { to: '/users', label: 'nav.users', icon: Users, minimumRole: 'admin' },
      { to: '/agents', label: 'nav.agents', icon: KeyRound, minimumRole: 'admin' },
      { to: '/notifications', label: 'nav.notifications', icon: BellRing, minimumRole: 'admin' },
      { to: '/audit', label: 'nav.audit', icon: FileClock, minimumRole: 'admin' },
      { to: '/settings', label: 'nav.settings', icon: Settings, minimumRole: 'admin' },
    ],
  },
] as const
type NavItem = (typeof navGroups)[number]['items'][number]

const visibleGroups = computed(() =>
  navGroups
    .map((group) => ({
      ...group,
      items: group.items.filter(
        (item) =>
          !('minimumRole' in item) ||
          roleOrder[session.user?.role ?? 'viewer'] >= roleOrder[item.minimumRole],
      ),
    }))
    .filter((group) => group.items.length),
)
const visibleItems = computed(() => visibleGroups.value.flatMap((group) => group.items))
const currentItem = computed(() =>
  visibleItems.value.find((item) => active(item.to, 'exact' in item && item.exact)),
)
const paletteItems = computed(() => {
  const needle = paletteQuery.value.trim().toLowerCase()
  return visibleItems.value.filter((item) => !needle || t(item.label).toLowerCase().includes(needle))
})

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

function toggleCollapsed(): void {
  collapsed.value = !collapsed.value
  localStorage.setItem('guardian_nav_collapsed', String(collapsed.value))
}

function changeLocale(event: Event): void {
  setLocale((event.target as HTMLSelectElement).value as SupportedLocale)
}

function keyboardShortcut(event: KeyboardEvent): void {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault()
    paletteOpen.value = !paletteOpen.value
    if (!paletteOpen.value) paletteQuery.value = ''
  }
  if (event.key === 'Escape') paletteOpen.value = false
}

async function navigate(item: NavItem): Promise<void> {
  paletteOpen.value = false
  paletteQuery.value = ''
  await router.push(item.to)
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
  window.addEventListener('keydown', keyboardShortcut)
})
onBeforeUnmount(() => window.removeEventListener('keydown', keyboardShortcut))

async function logout(): Promise<void> {
  await session.logout()
  await router.push('/login')
}
</script>

<template>
  <div class="operations-shell" :class="{ 'nav-collapsed': collapsed }">
    <button class="mobile-menu icon-button" type="button" :aria-label="t('nav.open')" @click="mobileOpen = true"><Menu :size="20" /></button>
    <div v-if="mobileOpen" class="nav-scrim" @click="mobileOpen = false"></div>
    <aside class="sidebar" :class="{ open: mobileOpen }">
      <div class="brand-row">
        <div class="brand-mark"><ShieldCheck :size="20" /></div>
        <div class="nav-copy"><strong>VPS Guardian</strong><span>{{ t('nav.controlCenter') }}</span></div>
        <button class="close-nav icon-button" type="button" :aria-label="t('nav.close')" @click="mobileOpen = false"><X :size="19" /></button>
      </div>
      <div class="controller-state">
        <Activity :size="16" />
        <div class="nav-copy"><span>{{ t('nav.currentSession') }}</span><strong>{{ t('nav.authenticated') }}</strong></div>
        <span class="live-dot"></span>
      </div>
      <nav class="primary-nav" :aria-label="t('nav.main')">
        <section v-for="group in visibleGroups" :key="group.label" class="nav-group">
          <h2 class="nav-copy">{{ t(group.label) }}</h2>
          <RouterLink
            v-for="item in group.items"
            :key="item.to"
            :to="item.to"
            :title="collapsed ? t(item.label) : undefined"
            :class="{ active: active(item.to, 'exact' in item && item.exact) }"
            @click="mobileOpen = false"
          >
            <component :is="item.icon" :size="17" />
            <span class="nav-copy">{{ t(item.label) }}</span>
            <ChevronRight v-if="active(item.to, 'exact' in item && item.exact)" class="nav-copy" :size="14" />
          </RouterLink>
        </section>
      </nav>
      <button class="nav-collapse-button" type="button" :aria-label="t('nav.collapse')" @click="toggleCollapsed">
        <ChevronRight v-if="collapsed" :size="15" /><ChevronLeft v-else :size="15" /><span class="nav-copy">{{ t('nav.collapse') }}</span>
      </button>
      <div class="sidebar-footer">
        <label class="language-select"><span class="sr-only">{{ t('locale.select') }}</span><select :value="locale" :aria-label="t('locale.select')" @change="changeLocale"><option value="en-US">English</option><option value="zh-CN">简体中文</option></select></label>
        <button class="theme-toggle" type="button" :aria-label="theme === 'dark' ? t('nav.switchLight') : t('nav.switchDark')" @click="toggleTheme"><Sun v-if="theme === 'dark'" :size="16" /><Moon v-else :size="16" /><span class="nav-copy">{{ theme === 'dark' ? t('nav.light') : t('nav.dark') }}</span></button>
        <a href="/docs" target="_blank" rel="noreferrer"><BookOpenCheck :size="16" /><span class="nav-copy">{{ t('nav.apiDocs') }}</span></a>
        <div class="user-row">
          <div class="user-avatar">{{ session.user?.email.slice(0, 1).toUpperCase() }}</div>
          <div class="nav-copy"><strong>{{ session.user?.email }}</strong><span>{{ session.user?.role }}</span></div>
          <button class="icon-button" type="button" :title="t('nav.logout')" :aria-label="t('nav.logout')" @click="logout"><LogOut :size="17" /></button>
        </div>
      </div>
    </aside>
    <main class="main-surface">
      <header class="workspace-bar">
        <div class="breadcrumbs"><span>VPS Guardian</span><ChevronRight :size="13" /><strong>{{ currentItem ? t(currentItem.label) : route.name }}</strong></div>
        <button class="command-trigger" type="button" @click="paletteOpen = true"><Search :size="15" /><span>{{ t('nav.search') }}</span><kbd>Ctrl K</kbd></button>
      </header>
      <RouterView />
    </main>
    <div v-if="paletteOpen" class="command-backdrop" @click.self="paletteOpen = false">
      <section class="command-palette" role="dialog" aria-modal="true" :aria-label="t('nav.search')">
        <label><Search :size="18" /><input v-model="paletteQuery" autofocus :placeholder="t('nav.searchPlaceholder')" /></label>
        <button v-for="item in paletteItems" :key="item.to" type="button" @click="navigate(item)"><component :is="item.icon" :size="16" /><span>{{ t(item.label) }}</span><ChevronRight :size="14" /></button>
      </section>
    </div>
  </div>
</template>
