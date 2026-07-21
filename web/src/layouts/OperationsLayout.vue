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

import { session } from '../session'

const route = useRoute()
const router = useRouter()
const mobileOpen = ref(false)
const theme = ref<'light' | 'dark'>('dark')
const roleOrder = { viewer: 0, operator: 1, admin: 2, owner: 3 }
const navItems = [
  { to: '/overview', label: '运营总览', icon: LayoutDashboard, exact: true },
  { to: '/hosts', label: '主机', icon: Server },
  { to: '/services', label: '服务', icon: Boxes },
  { to: '/incidents', label: '事故', icon: BellRing },
  { to: '/repairs', label: '修复', icon: Wrench },
  { to: '/recovery', label: '备份恢复', icon: ArchiveRestore, minimumRole: 'operator' },
  { to: '/approvals', label: '审批中心', icon: ClipboardCheck, minimumRole: 'operator' },
  { to: '/audit', label: '审计日志', icon: FileClock, minimumRole: 'admin' },
  { to: '/settings', label: '系统设置', icon: Settings, minimumRole: 'admin' },
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
    <button class="mobile-menu icon-button" type="button" aria-label="打开导航" @click="mobileOpen = true">
      <Menu :size="20" />
    </button>
    <div v-if="mobileOpen" class="nav-scrim" @click="mobileOpen = false"></div>
    <aside class="sidebar" :class="{ open: mobileOpen }">
      <div class="brand-row">
        <div class="brand-mark"><ShieldCheck :size="20" /></div>
        <div><strong>VPS Guardian</strong><span>控制中心</span></div>
        <button class="close-nav icon-button" type="button" aria-label="关闭导航" @click="mobileOpen = false">
          <X :size="19" />
        </button>
      </div>
      <div class="controller-state">
        <Activity :size="16" />
        <div><span>当前会话</span><strong>已认证</strong></div>
        <span class="live-dot"></span>
      </div>
      <nav class="primary-nav" aria-label="主导航">
        <RouterLink
          v-for="item in visibleItems"
          :key="item.to"
          :to="item.to"
          :class="{ active: active(item.to, 'exact' in item && item.exact) }"
          @click="mobileOpen = false"
        >
          <component :is="item.icon" :size="17" />
          <span>{{ item.label }}</span>
          <ChevronRight v-if="active(item.to, 'exact' in item && item.exact)" :size="14" />
        </RouterLink>
      </nav>
      <div class="sidebar-footer">
        <button class="theme-toggle" type="button" :aria-label="theme === 'dark' ? '切换到亮色模式' : '切换到暗色模式'" @click="toggleTheme">
          <Sun v-if="theme === 'dark'" :size="16" /><Moon v-else :size="16" />
          <span>{{ theme === 'dark' ? '亮色模式' : '暗色模式' }}</span>
        </button>
        <a href="/docs" target="_blank" rel="noreferrer"><BookOpenCheck :size="16" />API 文档</a>
        <div class="user-row">
          <div class="user-avatar">{{ session.user?.email.slice(0, 1).toUpperCase() }}</div>
          <div><strong>{{ session.user?.email }}</strong><span>{{ session.user?.role }}</span></div>
          <button class="icon-button" type="button" title="退出登录" aria-label="退出登录" @click="logout">
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
