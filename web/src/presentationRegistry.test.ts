import { describe, expect, it } from 'vitest'

import {
  agentLabel,
  auditActionLabel,
  auditActorLabel,
  auditSourceLabel,
  dataReasonLabel,
  healthLabel,
  healthTone,
  managementLabel,
  productLabel,
  regionLabel,
  resourceTypeLabel,
  resultLabel,
} from './presentationRegistry'

describe('presentation registry', () => {
  it('presents machine values in both supported locales', () => {
    expect(healthLabel('stale', 'zh-CN')).toBe('数据不新鲜')
    expect(managementLabel('pending_enrollment', 'en-US')).toBe('Enrollment pending')
    expect(agentLabel('never_seen', 'zh-CN')).toBe('从未上报')
    expect(resultLabel('denied', 'en-US')).toBe('Denied')
    expect(resourceTypeLabel('host', 'zh-CN')).toBe('主机')
  })

  it('uses safe fallbacks instead of exposing unknown raw codes', () => {
    expect(healthLabel('private_new_state', 'en-US')).toBe('Needs review')
    expect(resultLabel('private_new_result', 'zh-CN')).toBe('已记录')
    expect(resourceTypeLabel('private_resource', 'en-US')).toBe('Resource')
  })

  it('keeps raw audit codes out of the primary Chinese label', () => {
    expect(auditActionLabel('auth.login', 'Signed in', 'zh-CN')).toBe('用户登录')
    expect(auditActionLabel('private.action', 'Private action', 'zh-CN')).toBe('未知审计动作')
    expect(healthTone('offline')).toBe('critical')
  })

  it.each([
    ['guardian_and_komari', 'Guardian + Komari'],
    ['guardian', 'Guardian managed'],
    ['komari_only', 'Komari observed'],
    ['pending_enrollment', 'Enrollment pending'],
  ] as const)('presents host management state %s', (value, expected) => {
    expect(managementLabel(value, 'en-US')).toBe(expected)
  })

  it.each([
    ['online', 'Reporting'],
    ['stale', 'Heartbeat stale'],
    ['never_seen', 'Never reported'],
    ['revoked', 'Identity revoked'],
    ['not_installed', 'Not installed'],
  ] as const)('presents host heartbeat state %s', (value, expected) => {
    expect(agentLabel(value, 'en-US')).toBe(expected)
  })

  it('explains missing data and expands region codes', () => {
    expect(dataReasonLabel('no_guardian_agent', 'zh-CN')).toContain('Guardian Agent')
    expect(dataReasonLabel('never_connected', 'en-US')).toContain('never sent')
    expect(regionLabel('hk', 'zh-CN')).toBe('香港')
  })

  it.each([
    ['success', '成功'],
    ['denied', '已拒绝'],
    ['failed', '失败'],
    ['detected', '已检测'],
    ['skipped', '已跳过'],
    ['expired', '已过期'],
    ['partial', '部分完成'],
  ])('presents audit result %s', (value, expected) => {
    expect(resultLabel(value, 'zh-CN')).toBe(expected)
  })

  it('uses explicit unknown product fallbacks', () => {
    expect(productLabel('attention', 'private_state', 'zh-CN')).toBe('其他')
    expect(auditSourceLabel('internal_service', 'zh-CN')).toBe('Controller 内部服务')
    expect(auditActorLabel('system', 'Controller service', 'zh-CN')).toBe('Controller 服务')
  })
})
