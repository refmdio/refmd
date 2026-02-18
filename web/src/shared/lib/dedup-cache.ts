/**
 * Generic Value + Promise Deduplication Cache
 *
 * Provides a module-level cache for resolved values and a promise map
 * for deduplicating concurrent async initialization (e.g. React Strict Mode).
 *
 * @typeParam V - The cached value type
 * @typeParam P - The promise result type (defaults to V)
 */

export interface DedupCache<V, P = V> {
  getValue(key: string): V | undefined
  setValue(key: string, value: V): void
  removeValue(key: string): void
  getPromise(key: string): Promise<P> | undefined
  setPromise(key: string, promise: Promise<P>): void
  removePromise(key: string): void
  /** Clear both value and promise entries. If key is given, only that entry; otherwise all. */
  invalidate(key?: string): void
}

export function createDedupCache<V, P = V>(): DedupCache<V, P> {
  const values = new Map<string, V>()
  const promises = new Map<string, Promise<P>>()

  return {
    getValue: (key) => values.get(key),
    setValue: (key, value) => values.set(key, value),
    removeValue: (key) => { values.delete(key) },
    getPromise: (key) => promises.get(key),
    setPromise: (key, promise) => promises.set(key, promise),
    removePromise: (key) => { promises.delete(key) },
    invalidate(key?: string) {
      if (key) {
        values.delete(key)
        promises.delete(key)
      } else {
        values.clear()
        promises.clear()
      }
    },
  }
}
