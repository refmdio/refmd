/**
 * Generic Value + Promise Deduplication Cache
 *
 * Provides a module-level cache for resolved values and a promise map
 * for deduplicating concurrent async initialization (e.g. React Strict Mode).
 *
 * Supports per-key subscriptions so consumers can react to value changes
 * without polling.
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
  /** Subscribe to value changes for a specific key. Returns an unsubscribe function. */
  subscribe(key: string, listener: (value: V | undefined) => void): () => void
}

export function createDedupCache<V, P = V>(): DedupCache<V, P> {
  const values = new Map<string, V>()
  const promises = new Map<string, Promise<P>>()
  const listeners = new Map<string, Set<(value: V | undefined) => void>>()

  function notify(key: string): void {
    const subs = listeners.get(key)
    if (!subs) return
    const value = values.get(key)
    for (const cb of subs) cb(value)
  }

  return {
    getValue: (key) => values.get(key),
    setValue(key, value) {
      values.set(key, value)
      notify(key)
    },
    removeValue(key) {
      values.delete(key)
      notify(key)
    },
    getPromise: (key) => promises.get(key),
    setPromise: (key, promise) => promises.set(key, promise),
    removePromise: (key) => { promises.delete(key) },
    invalidate(key?: string) {
      if (key) {
        values.delete(key)
        promises.delete(key)
        notify(key)
      } else {
        const keys = [...values.keys()]
        values.clear()
        promises.clear()
        for (const k of keys) notify(k)
      }
    },
    subscribe(key, listener) {
      let subs = listeners.get(key)
      if (!subs) {
        subs = new Set()
        listeners.set(key, subs)
      }
      subs.add(listener)
      return () => {
        subs!.delete(listener)
        if (subs!.size === 0) listeners.delete(key)
      }
    },
  }
}
