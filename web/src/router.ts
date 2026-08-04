import { createRouter, createWebHistory } from 'vue-router'

import OperationsLayout from './layouts/OperationsLayout.vue'
import { hostRoutes } from './hostRoutes'
import { session } from './session'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('./views/LoginView.vue'),
      meta: { public: true },
    },
    {
      path: '/identity-setup',
      name: 'identity-setup',
      component: () => import('./views/IdentitySetupView.vue'),
    },
    {
      path: '/',
      component: OperationsLayout,
      children: [
        { path: '', redirect: '/overview' },
        { path: 'overview', name: 'overview', component: () => import('./views/OverviewView.vue') },
        { path: 'attention', name: 'attention', component: () => import('./views/AttentionView.vue') },
        ...hostRoutes,
        {
          path: 'port-traffic',
          name: 'port-traffic',
          component: () => import('./views/PortTrafficView.vue'),
        },
        { path: 'services', name: 'services', component: () => import('./views/ServicesView.vue') },
        { path: 'topology', name: 'topology', component: () => import('./views/TopologyView.vue') },
        { path: 'alerts', name: 'alerts', component: () => import('./views/AlertsView.vue') },
        {
          path: 'incidents',
          name: 'incidents',
          component: () => import('./views/IncidentsView.vue'),
        },
        { path: 'repairs', name: 'repairs', component: () => import('./views/RepairsView.vue') },
        {
          path: 'account-security',
          name: 'account-security',
          component: () => import('./views/AccountSecurityView.vue'),
        },
        {
          path: 'recovery',
          alias: 'backup',
          name: 'recovery',
          component: () => import('./views/RecoveryView.vue'),
          meta: { minimumRole: 'operator' },
        },
        {
          path: 'approvals',
          name: 'approvals',
          component: () => import('./views/ApprovalsView.vue'),
          meta: { minimumRole: 'operator' },
        },
        {
          path: 'audit',
          name: 'audit',
          component: () => import('./views/AuditView.vue'),
          meta: { minimumRole: 'admin' },
        },
        {
          path: 'security',
          name: 'security',
          component: () => import('./views/SecurityView.vue'),
          meta: { minimumRole: 'admin' },
        },
        {
          path: 'users',
          name: 'users',
          component: () => import('./views/UsersView.vue'),
          meta: { minimumRole: 'admin' },
        },
        {
          path: 'agents',
          name: 'agents',
          component: () => import('./views/AgentsView.vue'),
          meta: { minimumRole: 'admin' },
        },
        {
          path: 'notifications',
          name: 'notifications',
          component: () => import('./views/NotificationsView.vue'),
          meta: { minimumRole: 'admin' },
        },
        {
          path: 'settings',
          name: 'settings',
          component: () => import('./views/SettingsView.vue'),
          meta: { minimumRole: 'admin' },
        },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/overview' },
  ],
})

const roleOrder = { viewer: 0, auditor: 0, operator: 1, admin: 2, owner: 3 }

router.beforeEach(async (to) => {
  try {
    await session.restore()
  } catch {
    return false
  }
  if (to.meta.public) {
    if (!session.user) return true
    return session.user.identity_setup_required ? { name: 'identity-setup' } : { name: 'overview' }
  }
  if (!session.user) return { name: 'login', query: { redirect: to.fullPath } }
  if (session.user.identity_setup_required && to.name !== 'identity-setup') {
    return { name: 'identity-setup' }
  }
  if (!session.user.identity_setup_required && to.name === 'identity-setup') {
    return { name: 'overview' }
  }
  const minimum = to.meta.minimumRole as keyof typeof roleOrder | undefined
  if (minimum && roleOrder[session.user.role] < roleOrder[minimum]) return { name: 'overview' }
  return true
})

export default router
