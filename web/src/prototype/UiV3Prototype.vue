<script setup lang="ts">
import {
  Activity,
  ArchiveRestore,
  BellRing,
  Boxes,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  ClipboardCheck,
  Ellipsis,
  FileClock,
  Filter,
  LayoutDashboard,
  Menu,
  Moon,
  Network,
  PanelLeftClose,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Users,
  Wrench,
  X,
} from '@lucide/vue'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'

import {
  attentionEn,
  attentionZh,
  incidents,
  overviewSummaryEn,
  overviewSummaryZh,
  services,
  type IncidentFixture,
  type ServiceFixture,
  type Tone,
} from './fixtures'
import PrototypeStatus from '../components/v3/StatusBadge.vue'

type ViewName = 'overview' | 'services' | 'incidents'
type ThemeName = 'light' | 'dark'
type LocaleName = 'zh' | 'en'

const params = new URLSearchParams(location.search)
const requestedView = params.get('view')
const view = ref<ViewName>(
  requestedView === 'services' || requestedView === 'incidents' ? requestedView : 'overview',
)
const theme = ref<ThemeName>(params.get('theme') === 'dark' ? 'dark' : 'light')
const locale = ref<LocaleName>(params.get('locale') === 'en' ? 'en' : 'zh')
const mobileNavigationOpen = ref(false)
const detailOpen = ref(params.get('detail') === '1')
const evidenceOpen = ref(params.get('evidence') === '1')
const serviceFilter = ref<'all' | 'issues'>('all')
const selectedService = ref<ServiceFixture>(services[2])
const selectedIncident = ref<IncidentFixture>(incidents[0])

const copy = computed(() => {
  if (locale.value === 'en') {
    return {
      product: 'Operations control plane',
      overview: 'Overview',
      services: 'Services',
      incidents: 'Incidents',
      hosts: 'Hosts',
      topology: 'Topology',
      alerts: 'Alerts',
      repairs: 'Repairs',
      approvals: 'Approvals',
      recovery: 'Recovery',
      security: 'Security',
      users: 'Users',
      agents: 'Agents',
      notifications: 'Notifications',
      settings: 'Settings',
      groupObserve: 'OBSERVE',
      groupRespond: 'RESPOND',
      groupProtect: 'PROTECT',
      search: 'Search',
      refreshed: 'Updated 34 sec ago',
      refresh: 'Refresh',
      help: 'Help',
      staging: 'Staging',
      version: 'RC2',
      production: 'Production not deployed',
      pageOverviewTitle: 'Operational overview',
      pageOverviewDescription: 'Health, attention, recoverability and release gates in one view.',
      pageServicesTitle: 'Service checks',
      pageServicesDescription: 'Compare check health and inspect evidence without losing context.',
      pageIncidentsTitle: 'Incidents',
      pageIncidentsDescription: 'Prioritize active impact, ownership and the next decision.',
      needsAttention: 'Needs attention',
      attentionDescription: 'Only current items that require a decision or action.',
      level: 'Level',
      item: 'Item',
      impact: 'Impact',
      owner: 'Owner',
      updated: 'Updated',
      action: 'Next action',
      operationalPulse: 'Operational pulse',
      resources: 'Current resource use',
      cpu: 'CPU',
      memory: 'Memory',
      disk: 'Disk',
      network: 'Network',
      backupGate: 'Recoverability & release gate',
      verifiedBackup: 'Verified offsite backup',
      gate: 'Production gate',
      viewDetails: 'View details',
    }
  }
  return {
    product: '运维控制平面',
    overview: '概览',
    services: '服务检查',
    incidents: '事故',
    hosts: '主机',
    topology: '拓扑',
    alerts: '告警',
    repairs: '修复',
    approvals: '审批',
    recovery: '备份恢复',
    security: '安全',
    users: '用户',
    agents: 'Agent',
    notifications: '通知',
    settings: '设置',
    groupObserve: '观测',
    groupRespond: '响应',
    groupProtect: '保护',
    search: '全局搜索',
    refreshed: '34 秒前更新',
    refresh: '刷新',
    help: '帮助',
    staging: 'Staging',
    version: 'RC2',
    production: 'Production 未部署',
    pageOverviewTitle: '运行概览',
    pageOverviewDescription: '集中查看健康、待办、可恢复性与发布门禁。',
    pageServicesTitle: '服务检查',
    pageServicesDescription: '比较检查状态，在不丢失上下文的情况下查看证据。',
    pageIncidentsTitle: '事故',
    pageIncidentsDescription: '按影响、Owner 和下一步决策组织处置。',
    needsAttention: '需要处理',
    attentionDescription: '只显示当前需要决策或操作的项目。',
    level: '等级',
    item: '事项',
    impact: '影响',
    owner: 'Owner',
    updated: '更新时间',
    action: '下一步',
    operationalPulse: '运行脉搏',
    resources: '当前资源使用',
    cpu: 'CPU',
    memory: '内存',
    disk: '磁盘',
    network: '网络',
    backupGate: '可恢复性与发布门禁',
    verifiedBackup: '已验证异地备份',
    gate: 'Production Gate',
    viewDetails: '查看详情',
  }
})

const currentTitle = computed(() => {
  if (view.value === 'services') return copy.value.pageServicesTitle
  if (view.value === 'incidents') return copy.value.pageIncidentsTitle
  return copy.value.pageOverviewTitle
})

const currentDescription = computed(() => {
  if (view.value === 'services') return copy.value.pageServicesDescription
  if (view.value === 'incidents') return copy.value.pageIncidentsDescription
  return copy.value.pageOverviewDescription
})

const overviewSummary = computed(() =>
  locale.value === 'en' ? overviewSummaryEn : overviewSummaryZh,
)
const attention = computed(() => (locale.value === 'en' ? attentionEn : attentionZh))
const visibleServices = computed(() =>
  serviceFilter.value === 'issues'
    ? services.filter((service) => service.tone !== 'healthy')
    : services,
)

const navGroups = computed(() => [
  {
    label: copy.value.groupObserve,
    items: [
      { id: 'overview', label: copy.value.overview, icon: LayoutDashboard },
      { id: 'hosts', label: copy.value.hosts, icon: Server },
      { id: 'services', label: copy.value.services, icon: Boxes },
      { id: 'topology', label: copy.value.topology, icon: Network },
    ],
  },
  {
    label: copy.value.groupRespond,
    items: [
      { id: 'alerts', label: copy.value.alerts, icon: BellRing, count: 1 },
      { id: 'incidents', label: copy.value.incidents, icon: Activity, count: 2 },
      { id: 'repairs', label: copy.value.repairs, icon: Wrench },
      { id: 'approvals', label: copy.value.approvals, icon: ClipboardCheck },
    ],
  },
  {
    label: copy.value.groupProtect,
    items: [
      { id: 'recovery', label: copy.value.recovery, icon: ArchiveRestore },
      { id: 'security', label: copy.value.security, icon: ShieldCheck },
      { id: 'users', label: copy.value.users, icon: Users },
      { id: 'agents', label: copy.value.agents, icon: FileClock },
      { id: 'notifications', label: copy.value.notifications, icon: BellRing },
      { id: 'settings', label: copy.value.settings, icon: Settings },
    ],
  },
])

function updateUrl(): void {
  const next = new URL(location.href)
  next.searchParams.set('view', view.value)
  next.searchParams.set('theme', theme.value)
  next.searchParams.set('locale', locale.value)
  if (detailOpen.value) next.searchParams.set('detail', '1')
  else next.searchParams.delete('detail')
  if (evidenceOpen.value) next.searchParams.set('evidence', '1')
  else next.searchParams.delete('evidence')
  history.replaceState(null, '', next)
}

function navigate(id: string): void {
  if (id === 'overview' || id === 'services' || id === 'incidents') {
    view.value = id
    detailOpen.value = false
    evidenceOpen.value = false
    mobileNavigationOpen.value = false
  }
}

function selectService(service: ServiceFixture): void {
  selectedService.value = service
  detailOpen.value = true
}

function selectIncident(incident: IncidentFixture): void {
  selectedIncident.value = incident
  detailOpen.value = true
}

function handleEscape(event: KeyboardEvent): void {
  if (event.key !== 'Escape') return
  if (detailOpen.value) detailOpen.value = false
  else mobileNavigationOpen.value = false
}

watch([view, theme, locale, detailOpen, evidenceOpen], updateUrl)
watch(mobileNavigationOpen, (open) => {
  document.body.classList.toggle('prototype-lock-scroll', open)
})

onMounted(() => {
  document.documentElement.dataset.prototypeTheme = theme.value
  document.documentElement.lang = locale.value === 'zh' ? 'zh-CN' : 'en'
  window.addEventListener('keydown', handleEscape)
})

watch(theme, (value) => {
  document.documentElement.dataset.prototypeTheme = value
})
watch(locale, (value) => {
  document.documentElement.lang = value === 'zh' ? 'zh-CN' : 'en'
})
onBeforeUnmount(() => window.removeEventListener('keydown', handleEscape))

function statusLabel(tone: Tone): string {
  if (tone === 'healthy') return locale.value === 'en' ? 'Healthy' : '正常'
  if (tone === 'warning') return locale.value === 'en' ? 'Warning' : '警告'
  if (tone === 'critical') return locale.value === 'en' ? 'Critical' : '严重'
  if (tone === 'info') return locale.value === 'en' ? 'Info' : '信息'
  return locale.value === 'en' ? 'No data' : '无数据'
}
</script>

<template>
  <div class="proto-app">
    <div
      v-if="mobileNavigationOpen"
      class="proto-scrim"
      aria-hidden="true"
      @click="mobileNavigationOpen = false"
    ></div>

    <aside class="proto-sidebar" :class="{ open: mobileNavigationOpen }">
      <div class="proto-brand">
        <span class="proto-brand-mark"><ShieldCheck :size="20" /></span>
        <div>
          <strong>VPS Guardian</strong>
          <span>{{ copy.product }}</span>
        </div>
        <button
          class="proto-icon-button proto-mobile-close"
          type="button"
          aria-label="关闭导航"
          @click="mobileNavigationOpen = false"
        >
          <X :size="19" />
        </button>
      </div>

      <div class="proto-controller-state">
        <span class="proto-health-dot"></span>
        <div>
          <strong>Controller</strong>
          <span>{{ locale === 'en' ? 'Healthy · 2 agents online' : '正常 · 2 个 Agent 在线' }}</span>
        </div>
      </div>

      <nav class="proto-navigation" aria-label="主导航">
        <section v-for="group in navGroups" :key="group.label" class="proto-nav-group">
          <h2>{{ group.label }}</h2>
          <button
            v-for="item in group.items"
            :key="item.id"
            type="button"
            :class="{ active: view === item.id, muted: !['overview', 'services', 'incidents'].includes(item.id) }"
            :aria-current="view === item.id ? 'page' : undefined"
            @click="navigate(item.id)"
          >
            <component :is="item.icon" :size="17" aria-hidden="true" />
            <span>{{ item.label }}</span>
            <small v-if="item.count">{{ item.count }}</small>
          </button>
        </section>
      </nav>

      <div class="proto-sidebar-footer">
        <button type="button">
          <span class="proto-avatar">L</span>
          <span class="proto-account-copy">
            <strong title="owner@example.invalid">owner@example.invalid</strong>
            <small>Owner · Session 34m</small>
          </span>
          <ChevronRight :size="15" />
        </button>
      </div>
    </aside>

    <div class="proto-workspace">
      <header class="proto-topbar">
        <button
          class="proto-icon-button proto-mobile-menu"
          type="button"
          aria-label="打开导航"
          @click="mobileNavigationOpen = true"
        >
          <Menu :size="20" />
        </button>
        <div class="proto-environment">
          <span class="proto-environment-dot"></span>
          <strong>{{ copy.staging }}</strong>
          <span>·</span>
          <span>{{ copy.version }}</span>
          <span>·</span>
          <span>{{ copy.production }}</span>
        </div>
        <div class="proto-top-actions">
          <button class="proto-search-trigger" type="button">
            <Search :size="16" />
            <span>{{ copy.search }}</span>
            <kbd>Ctrl K</kbd>
          </button>
          <button class="proto-icon-button" type="button" :aria-label="copy.help" title="帮助">
            <CircleHelp :size="18" />
          </button>
          <button
            class="proto-icon-button"
            type="button"
            :aria-label="theme === 'light' ? '切换深色主题' : '切换浅色主题'"
            @click="theme = theme === 'light' ? 'dark' : 'light'"
          >
            <Moon v-if="theme === 'light'" :size="18" />
            <Sun v-else :size="18" />
          </button>
          <button class="proto-locale-button" type="button" @click="locale = locale === 'zh' ? 'en' : 'zh'">
            {{ locale === 'zh' ? '中' : 'EN' }}
          </button>
        </div>
      </header>

      <main class="proto-main">
        <header class="proto-page-header">
          <div>
            <p class="proto-eyebrow">{{ copy.staging }} / {{ currentTitle }}</p>
            <h1>{{ currentTitle }}</h1>
            <p>{{ currentDescription }}</p>
          </div>
          <div class="proto-page-actions">
            <span>{{ copy.refreshed }}</span>
            <button class="proto-button secondary" type="button"><RefreshCw :size="15" />{{ copy.refresh }}</button>
            <button v-if="view === 'services'" class="proto-button primary" type="button">
              <span aria-hidden="true">＋</span>新建检查
            </button>
          </div>
        </header>

        <template v-if="view === 'overview'">
          <section class="proto-summary-grid" aria-label="运行摘要">
            <button
              v-for="summary in overviewSummary"
              :key="summary.label"
              class="proto-summary"
              type="button"
            >
              <span class="proto-summary-head">
                <span>{{ summary.label }}</span>
                <PrototypeStatus :tone="summary.tone" :label="statusLabel(summary.tone)" compact />
              </span>
              <strong>{{ summary.value }}</strong>
              <span>{{ summary.detail }}</span>
              <small>{{ summary.updated }} <ChevronRight :size="13" /></small>
            </button>
          </section>

          <section class="proto-section">
            <div class="proto-section-heading">
              <div>
                <h2>{{ copy.needsAttention }}</h2>
                <p>{{ copy.attentionDescription }}</p>
              </div>
              <button class="proto-text-button" type="button">
                {{ locale === 'en' ? 'View queue' : '查看处置队列' }} <ChevronRight :size="14" />
              </button>
            </div>
            <div class="proto-table-shell">
              <table class="proto-table attention-table">
                <thead>
                  <tr>
                    <th>{{ copy.level }}</th>
                    <th>{{ copy.item }}</th>
                    <th>{{ copy.impact }}</th>
                    <th>{{ copy.owner }}</th>
                    <th>{{ copy.updated }}</th>
                    <th>{{ copy.action }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="row in attention" :key="row.title">
                    <td><PrototypeStatus :tone="row.tone" :label="row.level" compact /></td>
                    <td><strong>{{ row.title }}</strong><small>{{ row.type }}</small></td>
                    <td>{{ row.impact }}</td>
                    <td>{{ row.owner }}</td>
                    <td>{{ row.time }}</td>
                    <td><button class="proto-row-action" type="button">{{ row.action }} <ChevronRight :size="13" /></button></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section class="proto-section">
            <div class="proto-section-heading">
              <div>
                <h2>{{ copy.operationalPulse }}</h2>
                <p>{{ locale === 'en' ? 'Current values first; history loads on demand.' : '先看当前值，历史趋势按需加载。' }}</p>
              </div>
              <span class="proto-muted-label">{{ locale === 'en' ? 'Compared with previous hour' : '对比上一小时' }}</span>
            </div>
            <div class="proto-pulse-layout">
              <div class="proto-resource-panel">
                <h3>{{ copy.resources }}</h3>
                <div class="proto-resource-grid">
                  <div>
                    <span>{{ copy.cpu }}</span>
                    <strong>18%</strong>
                    <small class="down">↓ 3%</small>
                    <i><b style="width: 18%"></b></i>
                  </div>
                  <div>
                    <span>{{ copy.memory }}</span>
                    <strong>46%</strong>
                    <small class="up">↑ 2%</small>
                    <i><b style="width: 46%"></b></i>
                  </div>
                  <div>
                    <span>{{ copy.disk }}</span>
                    <strong>61%</strong>
                    <small class="flat">— 0%</small>
                    <i><b style="width: 61%"></b></i>
                  </div>
                  <div>
                    <span>{{ copy.network }}</span>
                    <strong>2.4 MB/s</strong>
                    <small class="down">↓ 11%</small>
                    <i><b style="width: 32%"></b></i>
                  </div>
                </div>
                <button class="proto-chart-placeholder" type="button">
                  <Activity :size="18" />
                  <span>{{ locale === 'en' ? 'Load 24-hour chart' : '加载 24 小时趋势图' }}</span>
                </button>
              </div>
              <div class="proto-gate-panel">
                <h3>{{ copy.backupGate }}</h3>
                <div class="proto-gate-row">
                  <PrototypeStatus tone="healthy" :label="locale === 'en' ? 'Recoverable' : '可恢复'" />
                  <div><strong>{{ copy.verifiedBackup }}</strong><span>Offsite · 7 {{ locale === 'en' ? 'hr ago' : '小时前' }}</span></div>
                  <span>RPO 7h · RTO 18m</span>
                </div>
                <div class="proto-gate-row">
                  <PrototypeStatus tone="info" :label="locale === 'en' ? 'Blocked' : '有阻塞项'" />
                  <div><strong>{{ copy.gate }}</strong><span>2 / 4 {{ locale === 'en' ? 'gates complete' : '项门禁完成' }}</span></div>
                  <span>CRL · 24h/7d</span>
                </div>
                <button class="proto-text-button" type="button">{{ copy.viewDetails }} <ChevronRight :size="14" /></button>
              </div>
            </div>
          </section>
        </template>

        <template v-else-if="view === 'services'">
          <section class="proto-inline-metrics" aria-label="检查摘要">
            <div><span>已配置</span><strong>7</strong></div>
            <div class="healthy"><span>正常</span><strong>5</strong></div>
            <div class="warning"><span>警告</span><strong>1</strong></div>
            <div class="critical"><span>严重</span><strong>0</strong></div>
            <div><span>无数据</span><strong>1</strong></div>
            <div><span>最近执行</span><strong class="small-value">18 秒前</strong></div>
          </section>

          <section class="proto-section">
            <div class="proto-toolbar">
              <label class="proto-field-search"><Search :size="16" /><input aria-label="搜索检查" placeholder="搜索名称、目标或类型" /></label>
              <div class="proto-segmented" aria-label="状态筛选">
                <button :class="{ active: serviceFilter === 'all' }" type="button" @click="serviceFilter = 'all'">全部 7</button>
                <button :class="{ active: serviceFilter === 'issues' }" type="button" @click="serviceFilter = 'issues'">只看异常 2</button>
              </div>
              <button class="proto-button secondary" type="button"><Filter :size="15" />筛选</button>
              <button class="proto-button secondary" type="button"><SlidersHorizontal :size="15" />分组</button>
              <button class="proto-button secondary density-button" type="button">紧凑 <ChevronDown :size="14" /></button>
            </div>

            <div class="proto-table-shell">
              <table class="proto-table services-table">
                <thead>
                  <tr>
                    <th>状态</th>
                    <th>检查</th>
                    <th>目标</th>
                    <th>类型</th>
                    <th>周期</th>
                    <th>连续失败</th>
                    <th>最近结果</th>
                    <th>延迟</th>
                    <th>更新时间</th>
                    <th>事故</th>
                    <th><span class="sr-only">操作</span></th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="service in visibleServices"
                    :key="service.id"
                    :class="{ selected: detailOpen && selectedService.id === service.id }"
                    tabindex="0"
                    @click="selectService(service)"
                    @keydown.enter="selectService(service)"
                  >
                    <td><PrototypeStatus :tone="service.tone" :label="statusLabel(service.tone)" compact /></td>
                    <td><strong>{{ service.name }}</strong><small>{{ service.id }}</small></td>
                    <td>{{ service.target }}</td>
                    <td>{{ service.type }}</td>
                    <td>{{ service.interval }}</td>
                    <td><span :class="{ 'warning-text': service.failures }">{{ service.failures }}</span></td>
                    <td>{{ service.result }}</td>
                    <td>{{ service.latency }}</td>
                    <td>{{ service.updated }}</td>
                    <td><a v-if="service.incident !== '—'" href="#" @click.prevent>{{ service.incident }}</a><span v-else>—</span></td>
                    <td><button class="proto-icon-button small" type="button" :aria-label="`${service.name} 的操作`"><Ellipsis :size="17" /></button></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="proto-pagination"><span>1–7 / 7</span><button type="button" disabled>上一页</button><button type="button" disabled>下一页</button></div>
          </section>

          <section class="proto-section observation-section">
            <div class="proto-section-heading">
              <div>
                <h2>Agent 观察摘要</h2>
                <p>结构化解析最近采集结果；原始证据默认关闭。</p>
              </div>
              <div class="proto-observation-counts"><span><b>12</b> 正常</span><span><b>1</b> 异常</span><span><b>0</b> 变化</span></div>
            </div>
            <div class="proto-observation-list">
              <button type="button" @click="selectedService = services[1]; detailOpen = true">
                <PrototypeStatus tone="healthy" label="正常" />
                <div><strong>systemd</strong><span>未发现失败的 systemd unit</span></div>
                <span>0 failed · 41 秒前</span>
                <ChevronRight :size="16" />
              </button>
              <button type="button" @click="selectedService = services[0]; detailOpen = true">
                <PrototypeStatus tone="healthy" label="正常" />
                <div><strong>Docker</strong><span>8 运行 · 8 Healthy · 0 Exited</span></div>
                <span>0 异常 · 34 秒前</span>
                <ChevronRight :size="16" />
              </button>
              <button type="button" @click="selectedService = services[2]; detailOpen = true">
                <PrototypeStatus tone="warning" label="警告" />
                <div><strong>TLS</strong><span>1 个证书进入 30 天提醒窗口</span></div>
                <span>18 天 · 2 分钟前</span>
                <ChevronRight :size="16" />
              </button>
            </div>
          </section>
        </template>

        <template v-else>
          <section class="proto-inline-metrics incident-metrics" aria-label="事故摘要">
            <div><span>活动事故</span><strong>2</strong></div>
            <div><span>未分配</span><strong>1</strong></div>
            <div class="critical"><span>S1 / S2</span><strong>0</strong></div>
            <div class="warning"><span>超过目标时间</span><strong>1</strong></div>
            <div class="healthy"><span>最近解决</span><strong>3</strong></div>
            <div><span>平均恢复时间</span><strong class="small-value">22 分钟</strong></div>
          </section>

          <section class="proto-section">
            <div class="proto-toolbar incident-toolbar">
              <label class="proto-field-search"><Search :size="16" /><input aria-label="搜索事故" placeholder="搜索标题、资源或 Owner" /></label>
              <div class="proto-segmented">
                <button class="active" type="button">活动 2</button>
                <button type="button">已解决 3</button>
                <button type="button">全部</button>
              </div>
              <button class="proto-button secondary" type="button"><Filter :size="15" />7 个筛选项</button>
              <button class="proto-button secondary" type="button">更新时间 <ChevronDown :size="14" /></button>
            </div>

            <div class="proto-table-shell">
              <table class="proto-table incidents-table">
                <thead>
                  <tr>
                    <th>等级</th>
                    <th>事故</th>
                    <th>影响资源</th>
                    <th>状态</th>
                    <th>Owner</th>
                    <th>来源</th>
                    <th>创建时间</th>
                    <th>持续时间</th>
                    <th>最后更新</th>
                    <th>下一步</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="incident in incidents"
                    :key="incident.id"
                    :class="{ selected: detailOpen && selectedIncident.id === incident.id }"
                    tabindex="0"
                    @click="selectIncident(incident)"
                    @keydown.enter="selectIncident(incident)"
                  >
                    <td><PrototypeStatus :tone="incident.tone" :label="incident.severity" compact /></td>
                    <td>
                      <strong>{{ incident.title }}</strong>
                      <small>{{ incident.id }} <span v-if="incident.test" class="proto-test-label">测试记录</span></small>
                    </td>
                    <td>{{ incident.resource }}</td>
                    <td>{{ incident.status }}</td>
                    <td>{{ incident.owner }}</td>
                    <td>{{ incident.source }}</td>
                    <td><time title="2026-07-25 09:14 HKT">{{ incident.created }}</time></td>
                    <td>{{ incident.duration }}</td>
                    <td>{{ incident.updated }}</td>
                    <td><button class="proto-row-action" type="button">{{ incident.next }} <ChevronRight :size="13" /></button></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="proto-list-foot">
              <span>历史测试事故已从全局健康聚合中隔离，并可通过筛选单独查看。</span>
              <strong>显示 3 项</strong>
            </div>
          </section>
        </template>
      </main>
    </div>

    <div v-if="detailOpen" class="proto-drawer-scrim" aria-hidden="true" @click="detailOpen = false"></div>
    <aside v-if="detailOpen" class="proto-detail-drawer" aria-label="详情" tabindex="-1">
      <header>
        <div>
          <p>{{ view === 'services' ? '检查详情' : '事故详情' }}</p>
          <h2>{{ view === 'services' ? selectedService.name : selectedIncident.title }}</h2>
        </div>
        <button class="proto-icon-button" type="button" aria-label="关闭详情" @click="detailOpen = false">
          <X :size="19" />
        </button>
      </header>

      <template v-if="view === 'services'">
        <section class="proto-drawer-summary">
          <PrototypeStatus :tone="selectedService.tone" :label="statusLabel(selectedService.tone)" />
          <p>{{ selectedService.result }}</p>
          <span>{{ selectedService.target }} · {{ selectedService.updated }}</span>
        </section>
        <section class="proto-definition-grid">
          <div><span>最近成功</span><strong>34 秒前</strong></div>
          <div><span>最近失败</span><strong>7 天前</strong></div>
          <div><span>24 小时成功率</span><strong>99.8%</strong></div>
          <div><span>最近延迟</span><strong>{{ selectedService.latency }}</strong></div>
          <div><span>执行周期</span><strong>{{ selectedService.interval }}</strong></div>
          <div><span>连续失败</span><strong>{{ selectedService.failures }}</strong></div>
        </section>
        <section class="proto-drawer-section">
          <h3>解析摘要</h3>
          <div v-if="selectedService.type === 'systemd'" class="proto-structured-result">
            <Check :size="18" />
            <div><strong>未发现失败的 systemd unit</strong><span>命令成功执行，返回空异常集合。</span></div>
          </div>
          <div v-else class="proto-structured-result">
            <Activity :size="18" />
            <div><strong>{{ selectedService.result }}</strong><span>证据已结构化解析，没有默认展示无关字段。</span></div>
          </div>
        </section>
        <section class="proto-drawer-section">
          <button class="proto-evidence-toggle" type="button" :aria-expanded="evidenceOpen" @click="evidenceOpen = !evidenceOpen">
            <span><strong>查看原始证据</strong><small>采集于 34 秒前 · 解析成功</small></span>
            <ChevronDown :class="{ rotated: evidenceOpen }" :size="17" />
          </button>
          <div v-if="evidenceOpen" class="proto-evidence">
            <div><span>格式化 JSON</span><button type="button">复制</button><button type="button">自动换行</button></div>
            <pre><code>{
  "source": "{{ selectedService.type }}",
  "status": "parsed",
  "summary": "{{ selectedService.result }}",
  "items": []
}</code></pre>
          </div>
        </section>
      </template>

      <template v-else>
        <section class="proto-drawer-summary">
          <div class="proto-drawer-status-row">
            <PrototypeStatus :tone="selectedIncident.tone" :label="selectedIncident.severity" />
            <PrototypeStatus tone="info" :label="selectedIncident.status" />
          </div>
          <p>当前没有服务中断；需要在到期窗口前完成处置决策。</p>
          <span>{{ selectedIncident.resource }} · Owner {{ selectedIncident.owner }}</span>
        </section>
        <section class="proto-definition-grid">
          <div><span>创建时间</span><strong>{{ selectedIncident.created }}</strong></div>
          <div><span>持续时间</span><strong>{{ selectedIncident.duration }}</strong></div>
          <div><span>最后更新</span><strong>{{ selectedIncident.updated }}</strong></div>
          <div><span>来源</span><strong>{{ selectedIncident.source }}</strong></div>
        </section>
        <section class="proto-drawer-section">
          <h3>下一步决策</h3>
          <div class="proto-next-action"><strong>{{ selectedIncident.next }}</strong><span>建议在 24 小时内确认 Owner 与执行窗口。</span><button class="proto-button primary" type="button">分配并开始</button></div>
        </section>
        <section class="proto-drawer-section">
          <h3>时间线</h3>
          <ol class="proto-timeline">
            <li><i></i><div><strong>证书检查触发警告</strong><span>12 分钟前 · 自动检测</span><p>剩余有效期进入 30 天提醒窗口。</p></div></li>
            <li><i></i><div><strong>事故已分配给 Liu</strong><span>8 分钟前 · Owner</span><p>等待确认续期维护窗口。</p></div></li>
          </ol>
        </section>
      </template>
    </aside>
  </div>
</template>
