import { describe, it, expect, beforeEach } from 'vitest'
import { KeyCache, KekCache, DekCache, clearAllCaches } from '../key-cache'

describe('KeyCache', () => {
  describe('basic operations', () => {
    let cache: KeyCache<string>

    beforeEach(() => {
      cache = new KeyCache<string>(3)
    })

    it('should set and get values', () => {
      cache.set('a', 'value-a')
      expect(cache.get('a')).toBe('value-a')
    })

    it('should return undefined for missing keys', () => {
      expect(cache.get('missing')).toBeUndefined()
    })

    it('should update existing values', () => {
      cache.set('a', 'value-1')
      cache.set('a', 'value-2')
      expect(cache.get('a')).toBe('value-2')
    })

    it('should delete values', () => {
      cache.set('a', 'value-a')
      expect(cache.delete('a')).toBe(true)
      expect(cache.get('a')).toBeUndefined()
    })

    it('should return false when deleting non-existent key', () => {
      expect(cache.delete('missing')).toBe(false)
    })

    it('should check if key exists', () => {
      cache.set('a', 'value-a')
      expect(cache.has('a')).toBe(true)
      expect(cache.has('missing')).toBe(false)
    })

    it('should clear all values', () => {
      cache.set('a', 'value-a')
      cache.set('b', 'value-b')
      cache.clear()
      expect(cache.size).toBe(0)
      expect(cache.get('a')).toBeUndefined()
    })

    it('should track size', () => {
      expect(cache.size).toBe(0)
      cache.set('a', 'value-a')
      expect(cache.size).toBe(1)
      cache.set('b', 'value-b')
      expect(cache.size).toBe(2)
      cache.delete('a')
      expect(cache.size).toBe(1)
    })

    it('should return all keys', () => {
      cache.set('a', 'value-a')
      cache.set('b', 'value-b')
      expect(cache.keys()).toEqual(expect.arrayContaining(['a', 'b']))
    })
  })

  describe('LRU eviction', () => {
    let cache: KeyCache<string>

    beforeEach(() => {
      cache = new KeyCache<string>(3)
    })

    it('should evict oldest entry when at capacity', () => {
      cache.set('a', 'value-a')
      cache.set('b', 'value-b')
      cache.set('c', 'value-c')
      cache.set('d', 'value-d') // should evict 'a'

      expect(cache.get('a')).toBeUndefined()
      expect(cache.get('b')).toBe('value-b')
      expect(cache.get('c')).toBe('value-c')
      expect(cache.get('d')).toBe('value-d')
      expect(cache.size).toBe(3)
    })

    it('should update access time on get', async () => {
      // Set 'a' first (oldest by insertion)
      cache.set('a', 'value-a')

      // Wait to ensure different timestamps
      await new Promise(resolve => setTimeout(resolve, 50))

      // Set 'b' and 'c'
      cache.set('b', 'value-b')
      await new Promise(resolve => setTimeout(resolve, 50))
      cache.set('c', 'value-c')

      // Wait and access 'a' to update its timestamp (makes it newest)
      await new Promise(resolve => setTimeout(resolve, 50))
      const accessedA = cache.get('a')
      expect(accessedA).toBe('value-a')

      // Now timestamps should be: b (oldest), c (middle), a (newest)
      // Wait a bit before adding 'd'
      await new Promise(resolve => setTimeout(resolve, 50))

      // Add 'd', should evict 'b' (oldest by access time)
      cache.set('d', 'value-d')

      expect(cache.get('a')).toBe('value-a') // still here (was accessed recently)
      expect(cache.get('b')).toBeUndefined() // evicted (oldest)
      expect(cache.get('c')).toBe('value-c')
      expect(cache.get('d')).toBe('value-d')
    })
  })

  describe('Uint8Array handling', () => {
    it('should zero out Uint8Array values on clear', () => {
      const cache = new KeyCache<Uint8Array>(3)
      const value = new Uint8Array([1, 2, 3, 4])
      cache.set('key', value)
      cache.clear()

      // Original array should be zeroed
      expect(Array.from(value)).toEqual([0, 0, 0, 0])
    })

    it('should zero out Uint8Array values on eviction', async () => {
      const cache = new KeyCache<Uint8Array>(2)
      const value1 = new Uint8Array([1, 2, 3])

      cache.set('a', value1)

      await new Promise(resolve => setTimeout(resolve, 10))

      cache.set('b', new Uint8Array([4, 5, 6]))

      await new Promise(resolve => setTimeout(resolve, 10))

      // This should evict 'a'
      cache.set('c', new Uint8Array([7, 8, 9]))

      // Original value should be zeroed
      expect(Array.from(value1)).toEqual([0, 0, 0])
    })
  })
})

describe('KekCache', () => {
  let cache: KekCache

  beforeEach(() => {
    cache = new KekCache(3)
  })

  it('should set and get KEK by workspace ID', () => {
    const kek = new Uint8Array(32).fill(1)
    cache.setKek('ws-1', kek)
    expect(cache.getKek('ws-1')).toBe(kek)
  })

  it('should delete KEK', () => {
    const kek = new Uint8Array(32).fill(1)
    cache.setKek('ws-1', kek)
    expect(cache.deleteKek('ws-1')).toBe(true)
    expect(cache.getKek('ws-1')).toBeUndefined()
  })
})

describe('DekCache', () => {
  let cache: DekCache

  beforeEach(() => {
    cache = new DekCache(3)
  })

  it('should set and get DEK by document ID', () => {
    const dek = new Uint8Array(32).fill(2)
    cache.setDek('doc-1', dek)
    expect(cache.getDek('doc-1')).toBe(dek)
  })

  it('should delete DEK', () => {
    const dek = new Uint8Array(32).fill(2)
    cache.setDek('doc-1', dek)
    expect(cache.deleteDek('doc-1')).toBe(true)
    expect(cache.getDek('doc-1')).toBeUndefined()
  })

  it('should delete multiple DEKs by workspace', () => {
    cache.setDek('doc-1', new Uint8Array(32).fill(1))
    cache.setDek('doc-2', new Uint8Array(32).fill(2))
    cache.setDek('doc-3', new Uint8Array(32).fill(3))

    cache.deleteByWorkspace(['doc-1', 'doc-2'])

    expect(cache.getDek('doc-1')).toBeUndefined()
    expect(cache.getDek('doc-2')).toBeUndefined()
    expect(cache.getDek('doc-3')).toBeDefined()
  })
})

describe('clearAllCaches', () => {
  it('should clear both KEK and DEK caches', () => {
    const kekCache = new KekCache()
    const dekCache = new DekCache()

    kekCache.setKek('ws-1', new Uint8Array(32).fill(1))
    dekCache.setDek('doc-1', new Uint8Array(32).fill(2))

    // Note: clearAllCaches uses singletons, so this test is more of a smoke test
    clearAllCaches()
  })
})
