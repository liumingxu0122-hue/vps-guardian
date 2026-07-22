import type { RouteRecordRaw } from 'vue-router'

export const hostRoutes: RouteRecordRaw[] = [
  {
    path: 'hosts',
    alias: 'vps',
    name: 'hosts',
    component: () => import('./views/HostsView.vue'),
  },
  {
    path: 'hosts/:hostId',
    alias: 'vps/:hostId',
    name: 'host-detail',
    component: () => import('./views/HostsView.vue'),
  },
]
