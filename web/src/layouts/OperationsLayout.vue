<script setup lang="ts">
import {
  Activity,
  ArchiveRestore,
  BellRing,
  BookOpenCheck,
  Boxes,
  ChevronRight,
  CircleHelp,
  ClipboardCheck,
  FileClock,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Sun,
  Users,
  Wrench,
  X,
} from '@lucide/vue'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { dashboard } from '../dashboard'
import { setLocale, type SupportedLocale } from '../i18n'
import { session } from '../session'

const route = useRoute()
const router = useRouter()
const { locale, t } = useI18n()
const mobileOpen = ref(false)
const accountOpen = ref(false)
const paletteOpen = ref(false)
const systemInfoOpen = ref(false)
const paletteQuery = ref('')
const paletteInput = ref<HTMLInputElement | null>(null)
const sidebarCollapsed = ref(false)
const mobileSidebar = ref<HTMLElement | null>(null)
const mobileMenuButton = ref<HTMLButtonElement | null>(null)
const theme = ref<'light' | 'dark'>('light')
const roleOrder = { viewer: 0, operator: 1, admin: 2, owner: 3 }
const navGroups = [
  {
    label: 'nav.groupOverview',
    items: [
      { to: '/overview', label: 'nav.overview', icon: LayoutDashboard, exact: true },
      { to: '/hosts', label: 'nav.hosts', icon: Server },
      { to: '/services', label: 'nav.services', icon: Boxes },
      { to: '/topology', label: 'nav.topology', icon: Network },
    ],
  },
  {
    label: 'nav.groupResponse',
    items: [
      { to: '/alerts', label: 'nav.alerts', icon: BellRing },
      { to: '/incidents', label: 'nav.incidents', icon: Activity },
      { to: '/repairs', label: 'nav.repairs', icon: Wrench },
      { to: '/approvals', label: 'nav.approvals', icon: ClipboardCheck, minimumRole: 'operator' },
    ],
  },
  {
    label: 'nav.groupProtection',
    items: [
      { to: '/recovery', label: 'nav.recovery', icon: ArchiveRestore, minimumRole: 'operator' },
      { to: '/account-security', label: 'nav.accountSecurity', icon: ShieldCheck },
      { to: '/security', label: 'nav.security', icon: ShieldCheck, minimumRole: 'admin' },
    ],
  },
  {
    label: 'nav.groupAdministration',
    items: [
      { to: '/users', label: 'nav.users', icon: Users, minimumRole: 'admin' },
      { to: '/agents', label: 'nav.agents', icon: KeyRound, minimumRole: 'admin' },
      { to: '/notifications', label: 'nav.notifications', icon: BellRing, minimumRole: 'admin' },
      { to: '/audit', label: 'nav.audit', icon: FileClock, minimumRole: 'admin' },
      { to: '/settings', label: 'nav.settings', icon: Settings, minimumRole: 'admin' },
    ],
  },
] as const

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
const stage = computed(() => dashboard.data?.environment.stage ?? 'staging')
const version = computed(() => dashboard.data?.environment.version ?? '…')
const releaseLabel = computed(() => {
  const rc = version.value.match(/rc(\d+)/i)
  if (rc) return `RC${rc[1]}`
  return version.value.match(/v?(\d+\.\d+\.\d+)/)?.[1] ?? 'Build'
})
const buildLabel = computed(() => version.value.match(/-([a-f0-9]{7,40})$/i)?.[1]?.slice(0, 7) ?? '')
const productionLabel = computed(() =>
  dashboard.data?.environment.production_deployed
    ? locale.value === 'zh-CN'
      ? 'Production 已部署'
      : 'Production deployed'
    : `Production ${t('overview.notDeployed')}`,
)
const paletteItems = computed(() => {
  const query = paletteQuery.value.trim().toLocaleLowerCase()
  const items = visibleGroups.value.flatMap((group) =>
    group.items.map((item) => ({
      to: item.to,
      label: t(item.label),
      group: t(group.label),
      icon: item.icon,
    })),
  )
  return query
    ? items.filter((item) =>
        `${item.label} ${item.group} ${item.to}`.toLocaleLowerCase().includes(query),
      )
    : items.slice(0, 8)
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

function toggleSidebar(): void {
  sidebarCollapsed.value = !sidebarCollapsed.value
  localStorage.setItem('guardian_sidebar_collapsed', String(sidebarCollapsed.value))
}

function changeLocale(value: SupportedLocale): void {
  setLocale(value)
}

function closeMobileNavigation(): void {
  mobileOpen.value = false
}

function openPalette(): void {
  paletteQuery.value = ''
  paletteOpen.value = true
}

function closePalette(): void {
  paletteOpen.value = false
}

async function navigateFromPalette(to: string): Promise<void> {
  closePalette()
  await router.push(to)
}

function handleEscape(event: KeyboardEvent): void {
  if ((event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === 'k') {
    event.preventDefault()
    paletteOpen.value ? closePalette() : openPalette()
    return
  }
  if (event.key === 'Tab' && mobileOpen.value && window.innerWidth <= 820) {
    const controls = [...(mobileSidebar.value?.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ) ?? [])].filter((element) => element.offsetParent !== null)
    if (!controls.length) return
    const first = controls[0]
    const last = controls.at(-1)!
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
    return
  }
  if (event.key !== 'Escape') return
  if (paletteOpen.value) closePalette()
  else if (systemInfoOpen.value) systemInfoOpen.value = false
  else if (accountOpen.value) accountOpen.value = false
  else closeMobileNavigation()
}

async function logout(): Promise<void> {
  accountOpen.value = false
  await session.logout()
  dashboard.clear()
  await router.push('/login')
}

watch(mobileOpen, async (open) => {
  document.body.classList.toggle('prototype-lock-scroll', open)
  if (open) {
    await nextTick()
    mobileSidebar.value?.querySelector<HTMLElement>('.proto-mobile-close')?.focus()
  } else {
    mobileMenuButton.value?.focus()
  }
})
watch(paletteOpen, async (open) => {
  document.body.classList.toggle('v3-palette-lock', open)
  if (open) {
    await nextTick()
    paletteInput.value?.focus()
  }
})

onMounted(() => {
  const saved = localStorage.getItem('guardian_theme')
  applyTheme(
    saved === 'light' || saved === 'dark'
      ? saved
      : window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light',
  )
  sidebarCollapsed.value = localStorage.getItem('guardian_sidebar_collapsed') === 'true'
  window.addEventListener('keydown', handleEscape)
  void dashboard.load().catch(() => undefined)
})

onBeforeUnmount(() => {
  document.body.classList.remove('prototype-lock-scroll')
  document.body.classList.remove('v3-palette-lock')
  window.removeEventListener('keydown', handleEscape)
})
</script>

<template>
  <div class="proto-app" :class="{ 'sidebar-collapsed': sidebarCollapsed }">
    <div v-if="mobileOpen" class="proto-scrim" aria-hidden="true" @click="closeMobileNavigation"></div>
    <aside ref="mobileSidebar" class="proto-sidebar" :class="{ open: mobileOpen }">
      <div class="proto-brand">
        <span class="proto-brand-mark"><ShieldCheck :size="20" /></span>
        <div class="proto-brand-copy"><strong>VPS Guardian</strong><span>{{ t('nav.controlCenter') }}</span></div>
        <button
          class="proto-icon-button proto-sidebar-collapse"
          type="button"
          :aria-label="sidebarCollapsed ? (locale === 'zh-CN' ? '展开导航' : 'Expand navigation') : (locale === 'zh-CN' ? '折叠导航' : 'Collapse navigation')"
          @click="toggleSidebar"
        >
          <PanelLeftOpen v-if="sidebarCollapsed" :size="18" />
          <PanelLeftClose v-else :size="18" />
        </button>
        <button class="proto-icon-button proto-mobile-close" type="button" :aria-label="t('nav.close')" @click="closeMobileNavigation"><X :size="19" /></button>
      </div>
      <div class="proto-controller-state">
        <span class="proto-health-dot"></span>
        <div><strong>Controller</strong><span>{{ t('nav.authenticated') }} · {{ dashboard.data?.agents.online ?? '—' }} Agent</span></div>
      </div>
      <nav class="proto-navigation" :aria-label="t('nav.main')">
        <section v-for="group in visibleGroups" :key="group.label" class="proto-nav-group">
          <h2>{{ t(group.label) }}</h2>
          <RouterLink
            v-for="item in group.items"
            :key="item.to"
            :to="item.to"
            custom
            v-slot="{ href, navigate }"
          >
            <a
              :href="href"
              :class="{ active: active(item.to, 'exact' in item && item.exact) }"
              :aria-current="active(item.to, 'exact' in item && item.exact) ? 'page' : undefined"
              :title="sidebarCollapsed ? t(item.label) : undefined"
              @click="(event) => { navigate(event); closeMobileNavigation() }"
            >
              <component :is="item.icon" :size="17" aria-hidden="true" />
              <span>{{ t(item.label) }}</span>
            </a>
          </RouterLink>
        </section>
      </nav>
      <div class="proto-sidebar-footer">
        <button type="button" :aria-expanded="accountOpen" @click="accountOpen = !accountOpen">
          <span class="proto-avatar">{{ session.user?.email.slice(0, 1).toUpperCase() }}</span>
          <span class="proto-account-copy">
            <strong :title="session.user?.email">{{ session.user?.email }}</strong>
            <small>{{ session.user?.role }}</small>
          </span>
          <ChevronRight :size="15" />
        </button>
        <div v-if="accountOpen" class="v3-account-menu">
          <RouterLink to="/account-security" @click="accountOpen = false"><ShieldCheck :size="16" />{{ t('nav.accountSecurity') }}</RouterLink>
          <button type="button" @click="toggleTheme"><Sun v-if="theme === 'dark'" :size="16" /><Moon v-else :size="16" />{{ theme === 'dark' ? t('nav.light') : t('nav.dark') }}</button>
          <button type="button" @click="changeLocale(locale === 'zh-CN' ? 'en-US' : 'zh-CN')"><span class="v3-language-icon">{{ locale === 'zh-CN' ? 'EN' : '中' }}</span>{{ locale === 'zh-CN' ? 'English' : '简体中文' }}</button>
          <a href="/docs" target="_blank" rel="noreferrer"><BookOpenCheck :size="16" />{{ t('nav.apiDocs') }}</a>
          <button type="button" @click="logout"><LogOut :size="16" />{{ t('nav.logout') }}</button>
        </div>
      </div>
    </aside>

    <div class="proto-workspace">
      <header class="proto-topbar">
        <button ref="mobileMenuButton" class="proto-icon-button proto-mobile-menu" type="button" :aria-label="t('nav.open')" @click="mobileOpen = true"><Menu :size="20" /></button>
        <button class="proto-environment rc5-environment-button" type="button" :aria-expanded="systemInfoOpen" @click="systemInfoOpen = !systemInfoOpen">
          <span class="proto-environment-dot"></span>
          <strong>{{ stage }}</strong><span>·</span><span>{{ releaseLabel }}</span><span v-if="buildLabel">·</span><span v-if="buildLabel" class="mono">{{ buildLabel }}</span><CircleHelp :size="14" aria-hidden="true" />
        </button>
        <section v-if="systemInfoOpen" class="rc5-system-popover" role="dialog" :aria-label="locale === 'zh-CN' ? '系统信息' : 'System information'">
          <div><span>{{ locale === 'zh-CN' ? '环境' : 'Environment' }}</span><strong>{{ stage }}</strong></div>
          <div><span>{{ locale === 'zh-CN' ? '版本' : 'Release' }}</span><strong>{{ version }}</strong></div>
          <div><span>Production</span><strong>{{ productionLabel }}</strong></div>
        </section>
        <div class="proto-top-actions">
          <button class="proto-search-trigger" type="button" :aria-label="t('nav.search')" @click="openPalette"><Search :size="16" /><span>{{ t('nav.search') }}</span><kbd>Ctrl K</kbd></button>
          <a class="proto-icon-button" href="/docs" target="_blank" rel="noreferrer" :aria-label="t('nav.apiDocs')"><CircleHelp :size="18" /></a>
          <button class="proto-icon-button" type="button" :aria-label="theme === 'light' ? t('nav.switchDark') : t('nav.switchLight')" @click="toggleTheme"><Moon v-if="theme === 'light'" :size="18" /><Sun v-else :size="18" /></button>
          <button class="proto-locale-button" type="button" :aria-label="t('locale.select')" @click="changeLocale(locale === 'zh-CN' ? 'en-US' : 'zh-CN')">{{ locale === 'zh-CN' ? '中' : 'EN' }}</button>
        </div>
      </header>

      <main class="proto-main">
        <RouterLink
          v-if="session.recoveryCodesRemaining !== null && session.recoveryCodesRemaining <= 2"
          class="recovery-warning"
          to="/account-security"
        >
          {{ t('identity.recoveryCodesLow', { count: session.recoveryCodesRemaining }) }}
        </RouterLink>
        <RouterView />
      </main>
    </div>

    <Teleport to="body">
      <div v-if="paletteOpen" class="v3-palette-backdrop" @mousedown.self="closePalette">
        <section
          class="v3-palette"
          role="dialog"
          aria-modal="true"
          :aria-label="locale === 'zh-CN' ? '搜索与导航' : 'Search and navigate'"
        >
          <label class="v3-palette-search">
            <Search :size="18" aria-hidden="true" />
            <input
              ref="paletteInput"
              v-model="paletteQuery"
              type="search"
              :placeholder="locale === 'zh-CN' ? '搜索页面与操作…' : 'Search pages and actions…'"
            />
            <kbd>Esc</kbd>
          </label>
          <div class="v3-palette-results">
            <button
              v-for="item in paletteItems"
              :key="item.to"
              type="button"
              @click="navigateFromPalette(item.to)"
            >
              <component :is="item.icon" :size="17" aria-hidden="true" />
              <span><strong>{{ item.label }}</strong><small>{{ item.group }}</small></span>
              <ChevronRight :size="15" aria-hidden="true" />
            </button>
            <p v-if="!paletteItems.length">{{ locale === 'zh-CN' ? '没有匹配页面' : 'No matching pages' }}</p>
          </div>
        </section>
      </div>
    </Teleport>
  </div>
</template>
