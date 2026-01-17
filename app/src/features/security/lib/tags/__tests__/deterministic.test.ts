import { describe, it, expect, beforeEach, afterEach } from 'vitest'

import { getSodium } from '@/shared/lib/crypto'
import {
  encryptTagDeterministic,
  encryptTags,
  buildTagLookupTable,
  decryptTag,
  decryptTags,
  TagLookupManager,
  getTagLookupManager,
  resetTagLookupManager,
  HMAC_KEY_SIZE,
} from '@/shared/lib/tags'

describe('deterministic tag encryption', () => {
  let testKek: Uint8Array

  beforeEach(async () => {
    // Generate a test KEK
    const sodium = await getSodium()
    testKek = sodium.randombytes_buf(HMAC_KEY_SIZE)
    resetTagLookupManager()
  })

  afterEach(() => {
    resetTagLookupManager()
  })

  describe('encryptTagDeterministic', () => {
    it('should produce deterministic output for same tag and key', async () => {
      const result1 = await encryptTagDeterministic('hello', testKek)
      const result2 = await encryptTagDeterministic('hello', testKek)
      expect(result1).toBe(result2)
    })

    it('should produce different output for different tags', async () => {
      const result1 = await encryptTagDeterministic('hello', testKek)
      const result2 = await encryptTagDeterministic('world', testKek)
      expect(result1).not.toBe(result2)
    })

    it('should produce different output for different keys', async () => {
      const sodium = await getSodium()
      const otherKek = sodium.randombytes_buf(HMAC_KEY_SIZE)

      const result1 = await encryptTagDeterministic('hello', testKek)
      const result2 = await encryptTagDeterministic('hello', otherKek)
      expect(result1).not.toBe(result2)
    })

    it('should normalize tags to lowercase', async () => {
      const result1 = await encryptTagDeterministic('Hello', testKek)
      const result2 = await encryptTagDeterministic('hello', testKek)
      const result3 = await encryptTagDeterministic('HELLO', testKek)
      expect(result1).toBe(result2)
      expect(result2).toBe(result3)
    })

    it('should trim whitespace from tags', async () => {
      const result1 = await encryptTagDeterministic('  hello  ', testKek)
      const result2 = await encryptTagDeterministic('hello', testKek)
      expect(result1).toBe(result2)
    })

    it('should return Base64-encoded string', async () => {
      const result = await encryptTagDeterministic('hello', testKek)
      // Base64 pattern: alphanumeric, +, /, and = for padding
      expect(result).toMatch(/^[A-Za-z0-9+/]+=*$/)
    })

    it('should throw for empty tag', async () => {
      await expect(encryptTagDeterministic('', testKek)).rejects.toThrow()
      await expect(encryptTagDeterministic('   ', testKek)).rejects.toThrow()
    })

    it('should throw for invalid KEK length', async () => {
      const shortKek = new Uint8Array(16)
      await expect(encryptTagDeterministic('hello', shortKek)).rejects.toThrow(/Invalid KEK length/)
    })
  })

  describe('encryptTags', () => {
    it('should encrypt multiple tags', async () => {
      const tags = ['hello', 'world', 'foo']
      const encrypted = await encryptTags(tags, testKek)
      expect(encrypted).toHaveLength(3)
      expect(encrypted[0]).not.toBe(encrypted[1])
      expect(encrypted[1]).not.toBe(encrypted[2])
    })

    it('should maintain order', async () => {
      const tags = ['alpha', 'beta', 'gamma']
      const encrypted = await encryptTags(tags, testKek)

      // Verify order by encrypting individually
      const alpha = await encryptTagDeterministic('alpha', testKek)
      const beta = await encryptTagDeterministic('beta', testKek)
      const gamma = await encryptTagDeterministic('gamma', testKek)

      expect(encrypted[0]).toBe(alpha)
      expect(encrypted[1]).toBe(beta)
      expect(encrypted[2]).toBe(gamma)
    })

    it('should handle empty array', async () => {
      const encrypted = await encryptTags([], testKek)
      expect(encrypted).toEqual([])
    })
  })

  describe('buildTagLookupTable and decryptTag', () => {
    it('should build lookup table and decrypt', async () => {
      const knownTags = ['hello', 'world']
      const table = await buildTagLookupTable(knownTags, testKek)

      const encrypted = await encryptTagDeterministic('hello', testKek)
      expect(decryptTag(encrypted, table)).toBe('hello')
    })

    it('should return null for unknown encrypted tag', async () => {
      const table = await buildTagLookupTable(['hello'], testKek)
      const unknownEncrypted = await encryptTagDeterministic('unknown', testKek)
      expect(decryptTag(unknownEncrypted, table)).toBeNull()
    })

    it('should deduplicate tags in lookup table', async () => {
      const table = await buildTagLookupTable(['Hello', 'HELLO', 'hello'], testKek)
      // Should only have one entry
      expect(table.size).toBe(1)
    })

    it('should handle empty array', async () => {
      const table = await buildTagLookupTable([], testKek)
      expect(table.size).toBe(0)
    })
  })

  describe('decryptTags', () => {
    it('should decrypt multiple tags', async () => {
      const knownTags = ['alpha', 'beta', 'gamma']
      const table = await buildTagLookupTable(knownTags, testKek)
      const encrypted = await encryptTags(knownTags, testKek)

      const decrypted = decryptTags(encrypted, table)
      expect(decrypted).toEqual(['alpha', 'beta', 'gamma'])
    })

    it('should return null for unknown tags', async () => {
      const table = await buildTagLookupTable(['known'], testKek)
      const encrypted = [
        await encryptTagDeterministic('known', testKek),
        await encryptTagDeterministic('unknown', testKek),
      ]

      const decrypted = decryptTags(encrypted, table)
      expect(decrypted).toEqual(['known', null])
    })
  })

  describe('TagLookupManager', () => {
    it('should encrypt and decrypt tags', async () => {
      const manager = new TagLookupManager()
      manager.setKek(testKek)

      const encrypted = await manager.encrypt('hello')
      const decrypted = await manager.decrypt(encrypted)
      expect(decrypted).toBe('hello')
    })

    it('should add known tags and decrypt them', async () => {
      const manager = new TagLookupManager()
      manager.setKek(testKek)
      manager.addKnownTags(['alpha', 'beta'])

      const encryptedAlpha = await encryptTagDeterministic('alpha', testKek)
      const encryptedBeta = await encryptTagDeterministic('beta', testKek)

      expect(await manager.decrypt(encryptedAlpha)).toBe('alpha')
      expect(await manager.decrypt(encryptedBeta)).toBe('beta')
    })

    it('should return null for unknown tags', async () => {
      const manager = new TagLookupManager()
      manager.setKek(testKek)
      manager.addKnownTags(['known'])

      const encryptedUnknown = await encryptTagDeterministic('unknown', testKek)
      expect(await manager.decrypt(encryptedUnknown)).toBeNull()
    })

    it('should clear all state', async () => {
      const manager = new TagLookupManager()
      manager.setKek(testKek)
      await manager.encrypt('hello')

      manager.clear()
      expect(manager.getKnownTags()).toEqual([])
    })

    it('should throw if KEK not set', async () => {
      const manager = new TagLookupManager()
      await expect(manager.encrypt('hello')).rejects.toThrow('KEK not set')
    })
  })

  describe('getTagLookupManager', () => {
    it('should return singleton instance', () => {
      const manager1 = getTagLookupManager()
      const manager2 = getTagLookupManager()
      expect(manager1).toBe(manager2)
    })

    it('should reset singleton', () => {
      const manager1 = getTagLookupManager()
      resetTagLookupManager()
      const manager2 = getTagLookupManager()
      expect(manager1).not.toBe(manager2)
    })
  })
})
