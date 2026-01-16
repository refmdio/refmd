/**
 * E2EE Key Cache
 *
 * LRU cache for KEK and DEK keys to avoid repeated API calls and decryption.
 */

/** Default cache sizes */
export const DEFAULT_KEK_CACHE_SIZE = 50
export const DEFAULT_DEK_CACHE_SIZE = 200

/** Cache entry with metadata */
interface CacheEntry<T> {
  value: T
  accessedAt: number
}

/**
 * LRU Cache implementation for encryption keys
 *
 * Keys are stored in memory only and cleared on page unload.
 */
export class KeyCache<T> {
  private cache: Map<string, CacheEntry<T>>
  private readonly maxSize: number

  constructor(maxSize: number) {
    this.cache = new Map()
    this.maxSize = maxSize
  }

  /**
   * Get a value from the cache
   */
  get(key: string): T | undefined {
    const entry = this.cache.get(key)
    if (!entry) {
      return undefined
    }

    // Update access time for LRU
    entry.accessedAt = Date.now()
    return entry.value
  }

  /**
   * Set a value in the cache
   */
  set(key: string, value: T): void {
    // If key already exists, update it
    if (this.cache.has(key)) {
      this.cache.set(key, {
        value,
        accessedAt: Date.now(),
      })
      return
    }

    // Evict oldest entries if at capacity
    if (this.cache.size >= this.maxSize) {
      this.evictOldest()
    }

    this.cache.set(key, {
      value,
      accessedAt: Date.now(),
    })
  }

  /**
   * Delete a value from the cache
   */
  delete(key: string): boolean {
    return this.cache.delete(key)
  }

  /**
   * Check if a key exists in the cache
   */
  has(key: string): boolean {
    return this.cache.has(key)
  }

  /**
   * Clear all entries from the cache
   */
  clear(): void {
    // Zero out key material before clearing
    for (const entry of this.cache.values()) {
      if (entry.value instanceof Uint8Array) {
        entry.value.fill(0)
      }
    }
    this.cache.clear()
  }

  /**
   * Get the current size of the cache
   */
  get size(): number {
    return this.cache.size
  }

  /**
   * Get all keys in the cache
   */
  keys(): string[] {
    return Array.from(this.cache.keys())
  }

  /**
   * Evict the oldest (least recently accessed) entry
   */
  private evictOldest(): void {
    let oldestKey: string | null = null
    let oldestTime = Infinity

    for (const [key, entry] of this.cache.entries()) {
      if (entry.accessedAt < oldestTime) {
        oldestTime = entry.accessedAt
        oldestKey = key
      }
    }

    if (oldestKey !== null) {
      // Zero out key material before eviction
      const entry = this.cache.get(oldestKey)
      if (entry?.value instanceof Uint8Array) {
        entry.value.fill(0)
      }
      this.cache.delete(oldestKey)
    }
  }
}

/**
 * Specialized cache for Workspace KEKs
 */
export class KekCache extends KeyCache<Uint8Array> {
  constructor(maxSize: number = DEFAULT_KEK_CACHE_SIZE) {
    super(maxSize)
  }

  /**
   * Get KEK by workspace ID
   */
  getKek(workspaceId: string): Uint8Array | undefined {
    return this.get(workspaceId)
  }

  /**
   * Set KEK for workspace
   */
  setKek(workspaceId: string, kek: Uint8Array): void {
    this.set(workspaceId, kek)
  }

  /**
   * Delete KEK for workspace
   */
  deleteKek(workspaceId: string): boolean {
    return this.delete(workspaceId)
  }
}

/**
 * Specialized cache for Document DEKs
 */
export class DekCache extends KeyCache<Uint8Array> {
  constructor(maxSize: number = DEFAULT_DEK_CACHE_SIZE) {
    super(maxSize)
  }

  /**
   * Get DEK by document ID
   */
  getDek(documentId: string): Uint8Array | undefined {
    return this.get(documentId)
  }

  /**
   * Set DEK for document
   */
  setDek(documentId: string, dek: Uint8Array): void {
    this.set(documentId, dek)
  }

  /**
   * Delete DEK for document
   */
  deleteDek(documentId: string): boolean {
    return this.delete(documentId)
  }

  /**
   * Delete all DEKs for documents in a workspace
   * (useful when workspace KEK is rotated)
   */
  deleteByWorkspace(documentIds: string[]): void {
    for (const docId of documentIds) {
      this.delete(docId)
    }
  }
}

// Singleton instances
let kekCacheInstance: KekCache | null = null
let dekCacheInstance: DekCache | null = null

/**
 * Get the singleton KEK cache instance
 */
export function getKekCache(): KekCache {
  if (!kekCacheInstance) {
    kekCacheInstance = new KekCache()
  }
  return kekCacheInstance
}

/**
 * Get the singleton DEK cache instance
 */
export function getDekCache(): DekCache {
  if (!dekCacheInstance) {
    dekCacheInstance = new DekCache()
  }
  return dekCacheInstance
}

/**
 * Clear all key caches (for logout/lock)
 */
export function clearAllCaches(): void {
  kekCacheInstance?.clear()
  dekCacheInstance?.clear()
}
