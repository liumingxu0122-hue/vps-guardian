import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import { hostRoutes } from './hostRoutes'

function testRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: { template: '<router-view />' }, children: hostRoutes }],
  })
}

describe('VPS route aliases', () => {
  it('resolves both VPS and legacy host list routes to the same view', () => {
    const router = testRouter()

    expect(router.resolve('/vps').name).toBe('hosts')
    expect(router.resolve('/hosts').name).toBe('hosts')
  })

  it('preserves the opaque host ID on VPS detail routes', () => {
    const router = testRouter()
    const hostId = '1f5be8d7-9469-41d5-b14d-9dadf53555be'
    const resolved = router.resolve(`/vps/${hostId}`)

    expect(resolved.name).toBe('host-detail')
    expect(resolved.params.hostId).toBe(hostId)
  })
})
