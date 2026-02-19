/**
 * DSK Capability — Browser support detection
 *
 * Tests whether IndexedDB can persist non-exportable CryptoKey objects.
 * Some browsers/environments (incognito mode, certain mobile browsers)
 * cannot persist structured-clone CryptoKey objects.
 */

/**
 * Cached result of canPersistDsk() - null means not yet tested
 */
let dskCapabilityCache: boolean | null = null

/**
 * Test whether IndexedDB can persist non-exportable CryptoKey objects.
 *
 * Performs a roundtrip test: generate → store → load → encrypt.
 * The result is cached after the first call.
 */
export async function canPersistDsk(): Promise<boolean> {
  if (dskCapabilityCache !== null) return dskCapabilityCache
  if (typeof indexedDB === 'undefined') return false

  const testDbName = 'refmd-dsk-probe'
  const testStoreName = 'probe'
  const testKey = 'dsk-test'

  try {
    // Generate a test non-exportable key
    const testCryptoKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )

    // Write to IndexedDB
    const db: IDBDatabase = await new Promise((resolve, reject) => {
      const req = indexedDB.open(testDbName, 1)
      req.onerror = () => reject(req.error)
      req.onsuccess = () => resolve(req.result)
      req.onupgradeneeded = (e) => {
        const d = (e.target as IDBOpenDBRequest).result
        if (!d.objectStoreNames.contains(testStoreName)) {
          d.createObjectStore(testStoreName)
        }
      }
    })

    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(testStoreName, 'readwrite')
      const store = tx.objectStore(testStoreName)
      const req = store.put(testCryptoKey, testKey)
      req.onerror = () => reject(req.error)
      req.onsuccess = () => resolve()
      tx.oncomplete = () => {}
    })

    // Read back
    const loaded: CryptoKey | undefined = await new Promise((resolve, reject) => {
      const tx = db.transaction(testStoreName, 'readonly')
      const store = tx.objectStore(testStoreName)
      const req = store.get(testKey)
      req.onerror = () => reject(req.error)
      req.onsuccess = () => resolve(req.result as CryptoKey | undefined)
    })

    db.close()

    // Verify it's usable by encrypting a test message
    if (loaded) {
      const testData = new Uint8Array([1, 2, 3, 4])
      const iv = crypto.getRandomValues(new Uint8Array(12))
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, loaded, testData)
      dskCapabilityCache = true
    } else {
      dskCapabilityCache = false
    }
  } catch {
    dskCapabilityCache = false
  } finally {
    // Clean up test database
    try {
      indexedDB.deleteDatabase(testDbName)
    } catch {
      // Ignore cleanup errors
    }
  }

  return dskCapabilityCache
}
