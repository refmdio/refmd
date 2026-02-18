import { describe, it, expect, beforeEach } from 'vitest'
import {
  checkKeyVersionRollback,
  pinKeyVersion,
  assertAndPinKeyVersion,
  checkAndPinKeyVersion,
  getKeyVersionPin,
  clearAllKeyVersionPins,
} from './index'

// Uses fake-indexeddb (auto-registered via vitest setupFiles)

describe('anti-rollback key version helpers', () => {
  beforeEach(async () => {
    await clearAllKeyVersionPins()
  })

  describe('checkKeyVersionRollback', () => {
    it('returns rolledBack: false when no pin exists', async () => {
      const result = await checkKeyVersionRollback('kek', 'ws-1', 1)
      expect(result.rolledBack).toBe(false)
    })

    it('returns rolledBack: false when version >= pinned', async () => {
      await pinKeyVersion({ type: 'kek', id: 'ws-1', highestVersion: 3, observedAt: Date.now() })
      const result = await checkKeyVersionRollback('kek', 'ws-1', 3)
      expect(result.rolledBack).toBe(false)
    })

    it('returns rolledBack: true when version < pinned', async () => {
      await pinKeyVersion({ type: 'kek', id: 'ws-1', highestVersion: 5, observedAt: Date.now() })
      const result = await checkKeyVersionRollback('kek', 'ws-1', 3)
      expect(result.rolledBack).toBe(true)
      if (result.rolledBack) {
        expect(result.pinnedVersion).toBe(5)
      }
    })
  })

  describe('assertAndPinKeyVersion', () => {
    it('pins version when no rollback', async () => {
      await assertAndPinKeyVersion('dek', 'doc-1', 2)
      const pin = await getKeyVersionPin('dek', 'doc-1')
      expect(pin).not.toBeNull()
      expect(pin!.highestVersion).toBe(2)
    })

    it('throws on rollback', async () => {
      await pinKeyVersion({ type: 'dek', id: 'doc-1', highestVersion: 5, observedAt: Date.now() })
      await expect(assertAndPinKeyVersion('dek', 'doc-1', 3)).rejects.toThrow('rollback detected')
    })
  })

  describe('checkAndPinKeyVersion', () => {
    it('returns true and pins when no rollback', async () => {
      const ok = await checkAndPinKeyVersion('kek', 'ws-2', 4)
      expect(ok).toBe(true)
      const pin = await getKeyVersionPin('kek', 'ws-2')
      expect(pin!.highestVersion).toBe(4)
    })

    it('returns false on rollback (no throw)', async () => {
      await pinKeyVersion({ type: 'kek', id: 'ws-2', highestVersion: 10, observedAt: Date.now() })
      const ok = await checkAndPinKeyVersion('kek', 'ws-2', 5)
      expect(ok).toBe(false)
    })
  })
})
