/**
 * IndexedDB Common Helpers
 *
 * Shared open/transaction wrappers used by trust-store, anti-rollback, and dsk modules.
 *
 * IMPORTANT: All write helpers resolve on `tx.oncomplete` (not `request.onsuccess`)
 * to guarantee data is durably committed before the caller continues.
 */

/**
 * Convert a Uint8Array to an ArrayBuffer suitable for IndexedDB storage.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

/**
 * Open an IndexedDB database with upgrade handler.
 */
export function openIdb(
  name: string,
  version: number,
  onUpgrade: (db: IDBDatabase) => void
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, version)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result
      onUpgrade(db)
    }
  })
}

/**
 * Get a value from an IndexedDB object store.
 */
export function idbGet<T>(db: IDBDatabase, storeName: string, key: IDBValidKey): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly')
    const store = tx.objectStore(storeName)
    const request = store.get(key)

    request.onerror = () => reject(request.error)
    tx.oncomplete = () => {
      resolve(request.result as T | undefined)
      db.close()
    }
    tx.onerror = () => reject(tx.error)
  })
}

/**
 * Put a value into an IndexedDB object store.
 */
export function idbPut(db: IDBDatabase, storeName: string, value: unknown, key?: IDBValidKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite')
    const store = tx.objectStore(storeName)
    const request = key !== undefined ? store.put(value, key) : store.put(value)

    request.onerror = () => reject(request.error)
    tx.oncomplete = () => {
      resolve()
      db.close()
    }
    tx.onerror = () => reject(tx.error)
  })
}

/**
 * Delete a value from an IndexedDB object store.
 */
export function idbDelete(db: IDBDatabase, storeName: string, key: IDBValidKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite')
    const store = tx.objectStore(storeName)
    const request = store.delete(key)

    request.onerror = () => reject(request.error)
    tx.oncomplete = () => {
      resolve()
      db.close()
    }
    tx.onerror = () => reject(tx.error)
  })
}

/**
 * Atomic get-then-conditional-put in a single readwrite transaction.
 * Used by anti-rollback pins to prevent version downgrades.
 *
 * @param shouldUpdate Return true to proceed with the put, false to skip.
 */
export function idbConditionalPut<T>(
  db: IDBDatabase,
  storeName: string,
  key: IDBValidKey,
  value: T,
  shouldUpdate: (existing: T | undefined) => boolean
): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite')
    const store = tx.objectStore(storeName)

    const getRequest = store.get(key)
    getRequest.onerror = () => reject(getRequest.error)
    getRequest.onsuccess = () => {
      const existing = getRequest.result as T | undefined
      if (!shouldUpdate(existing)) {
        tx.abort()
        return
      }
      const putRequest = store.put(value)
      putRequest.onerror = () => reject(putRequest.error)
    }

    tx.oncomplete = () => {
      resolve()
      db.close()
    }
    tx.onabort = () => {
      // Abort from shouldUpdate returning false — not an error
      resolve()
      db.close()
    }
    tx.onerror = () => reject(tx.error)
  })
}

/**
 * Clear all values from an IndexedDB object store.
 */
export function idbClear(db: IDBDatabase, storeName: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite')
    const store = tx.objectStore(storeName)
    const request = store.clear()

    request.onerror = () => reject(request.error)
    tx.oncomplete = () => {
      resolve()
      db.close()
    }
    tx.onerror = () => reject(tx.error)
  })
}
