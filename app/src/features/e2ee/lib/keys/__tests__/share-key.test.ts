import { describe, it, expect, beforeAll } from 'vitest'
import {
  generateShareKey,
  extractShareKeyFromFragment,
  hasShareKeyFragment,
  buildShareUrl,
  URL_FRAGMENT_PREFIX,
  SHARE_KEY_SIZE,
} from '../share-key'
import { getSodium } from '../../crypto'

describe('Share Key', () => {
  beforeAll(async () => {
    // Initialize sodium
    await getSodium()
  })

  describe('generateShareKey', () => {
    it('should generate a key and fragment', async () => {
      const result = await generateShareKey()

      expect(result.key).toBeInstanceOf(Uint8Array)
      expect(result.key.length).toBe(SHARE_KEY_SIZE)
      expect(result.fragment).toMatch(new RegExp(`^${URL_FRAGMENT_PREFIX}`))
    })

    it('should generate unique keys', async () => {
      const result1 = await generateShareKey()
      const result2 = await generateShareKey()

      expect(result1.key).not.toEqual(result2.key)
      expect(result1.fragment).not.toBe(result2.fragment)
    })
  })

  describe('extractShareKeyFromFragment', () => {
    it('should extract key from valid fragment', async () => {
      const original = await generateShareKey()
      const extracted = await extractShareKeyFromFragment(original.fragment)

      expect(extracted).toBeInstanceOf(Uint8Array)
      expect(Array.from(extracted!)).toEqual(Array.from(original.key))
    })

    it('should handle fragment with leading #', async () => {
      const original = await generateShareKey()
      const extracted = await extractShareKeyFromFragment('#' + original.fragment)

      expect(extracted).toBeInstanceOf(Uint8Array)
      expect(Array.from(extracted!)).toEqual(Array.from(original.key))
    })

    it('should return null for invalid fragment', async () => {
      const result = await extractShareKeyFromFragment('invalid')
      expect(result).toBeNull()
    })

    it('should return null for fragment without prefix', async () => {
      const result = await extractShareKeyFromFragment('other=value')
      expect(result).toBeNull()
    })

    it('should return null for empty fragment', async () => {
      const result = await extractShareKeyFromFragment('')
      expect(result).toBeNull()
    })
  })

  describe('hasShareKeyFragment', () => {
    it('should return true for valid fragment', async () => {
      const { fragment } = await generateShareKey()
      expect(hasShareKeyFragment(fragment)).toBe(true)
    })

    it('should return true for fragment with leading #', async () => {
      const { fragment } = await generateShareKey()
      expect(hasShareKeyFragment('#' + fragment)).toBe(true)
    })

    it('should return false for invalid fragment', () => {
      expect(hasShareKeyFragment('invalid')).toBe(false)
      expect(hasShareKeyFragment('')).toBe(false)
      expect(hasShareKeyFragment('#other=value')).toBe(false)
    })
  })

  describe('buildShareUrl', () => {
    it('should build URL with fragment', () => {
      const url = buildShareUrl('https://refmd.io/share/abc123', 'key=xyz')
      expect(url).toBe('https://refmd.io/share/abc123#key=xyz')
    })

    it('should replace existing fragment', () => {
      const url = buildShareUrl('https://refmd.io/share/abc123#old', 'key=xyz')
      expect(url).toBe('https://refmd.io/share/abc123#key=xyz')
    })

    it('should work with generated fragment', async () => {
      const { fragment } = await generateShareKey()
      const url = buildShareUrl('https://refmd.io/share/abc123', fragment)
      expect(url).toBe(`https://refmd.io/share/abc123#${fragment}`)
    })
  })
})
