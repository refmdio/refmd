/**
 * Tests for useKekRotation pure helpers.
 */

import { describe, it, expect } from 'vitest'
import { buildFingerprintMap, filterBlockedDevices, type RotationContext } from '../lib/kek-rotation-service'
import type { KeyChangeWarningItem } from '@/shared/hooks'

describe('buildFingerprintMap', () => {
  it('maps fingerprints to device IDs', () => {
    const items = [
      { newFingerprint: 'fp1', tofuNewEntry: { deviceId: 'dev1' } },
      { newFingerprint: 'fp2', tofuNewEntry: { deviceId: 'dev2' } },
    ] as KeyChangeWarningItem[]
    const map = buildFingerprintMap(items)
    expect(map.get('fp1')).toBe('dev1')
    expect(map.get('fp2')).toBe('dev2')
    expect(map.size).toBe(2)
  })

  it('handles empty items', () => {
    const map = buildFingerprintMap([])
    expect(map.size).toBe(0)
  })

  it('last item wins on duplicate fingerprints', () => {
    const items = [
      { newFingerprint: 'fp1', tofuNewEntry: { deviceId: 'dev1' } },
      { newFingerprint: 'fp1', tofuNewEntry: { deviceId: 'dev2' } },
    ] as KeyChangeWarningItem[]
    const map = buildFingerprintMap(items)
    expect(map.get('fp1')).toBe('dev2')
    expect(map.size).toBe(1)
  })
})

describe('filterBlockedDevices', () => {
  it('keeps devices that were trusted', () => {
    const ctx: RotationContext = {
      activeDevices: [{ id: 'a' }, { id: 'b' }, { id: 'c' }] as any,
      workspacesToRotate: [],
      documentsForRotation: [],
      dialogDeviceIds: new Set(['a', 'b']),
      trustedDeviceIds: new Set(['a']),
    }
    const result = filterBlockedDevices(ctx)
    expect(result.map(d => d.id)).toEqual(['a', 'c'])
  })

  it('keeps all devices when none shown in dialog', () => {
    const ctx: RotationContext = {
      activeDevices: [{ id: 'a' }, { id: 'b' }] as any,
      workspacesToRotate: [],
      documentsForRotation: [],
      dialogDeviceIds: new Set(),
      trustedDeviceIds: new Set(),
    }
    const result = filterBlockedDevices(ctx)
    expect(result.map(d => d.id)).toEqual(['a', 'b'])
  })

  it('removes all dialog devices when none trusted', () => {
    const ctx: RotationContext = {
      activeDevices: [{ id: 'a' }, { id: 'b' }, { id: 'c' }] as any,
      workspacesToRotate: [],
      documentsForRotation: [],
      dialogDeviceIds: new Set(['a', 'b']),
      trustedDeviceIds: new Set(),
    }
    const result = filterBlockedDevices(ctx)
    expect(result.map(d => d.id)).toEqual(['c'])
  })
})
