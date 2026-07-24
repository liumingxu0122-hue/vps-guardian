import type { RouteRecordRaw } from 'vue-router'

export const hostRoutes: RouteRecordRaw[] = [
  {
    path: 'hosts',
    alias: 'vps',
    name: 'hosts',
    component: () => import('./views/HostsEntryView.vue'),
    meta: { publicReadOnly: true },
  },
  {
    path: 'hosts/:hostId',
    alias: 'vps/:hostId',
    name: 'host-detail',
    component: () => import('./views/HostsEntryView.vue'),
  },
]
