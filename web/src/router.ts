import { createRouter, createWebHistory } from 'vue-router'

import OperationsLayout from './layouts/OperationsLayout.vue'
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
      path: '/',
      component: OperationsLayout,
      children: [
        { path: '', redirect: '/overview' },
        { path: 'overview', name: 'overview', component: () => import('./views/OverviewView.vue') },
        { path: 'hosts', name: 'hosts', component: () => import('./views/HostsView.vue') },
        { path: 'hosts/:hostId', name: 'host-detail', component: () => import('./views/HostsView.vue') },
        { path: 'services', name: 'services', component: () => import('./views/ServicesView.vue') },
        {
          path: 'incidents',
          name: 'incidents',
          component: () => import('./views/IncidentsView.vue'),
        },
        { path: 'repairs', name: 'repairs', component: () => import('./views/RepairsView.vue') },
        {
          path: 'recovery',
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

const roleOrder = { viewer: 0, operator: 1, admin: 2, owner: 3 }

router.beforeEach(async (to) => {
  await session.restore()
  if (to.meta.public) return session.user ? { name: 'overview' } : true
  if (!session.user) return { name: 'login', query: { redirect: to.fullPath } }
  const minimum = to.meta.minimumRole as keyof typeof roleOrder | undefined
  if (minimum && roleOrder[session.user.role] < roleOrder[minimum]) return { name: 'overview' }
  return true
})

export default router
