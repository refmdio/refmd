/**
 * DSK Store — IndexedDB helpers and DSK CRUD
 *
 * Manages the Device Storage Key (non-exportable AES-256-GCM key)
 * lifecycle: generate, store, load, and database operations.
 */

import { openIdb, idbGet, idbPut, idbDelete } from '@/shared/lib/idb'

const DB_NAME = 'refmd-crypto'
const DB_VERSION = 1
const STORE_NAME = 'keys'
export const DSK_KEY = 'dsk'
export const WRAPPED_UMK_KEY = 'wrapped-umk'
export const DEVICE_KEYS_KEY = 'device-keys'
export const DEVICE_ID_KEY = 'device-id'

function openDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(STORE_NAME)) {
      db.createObjectStore(STORE_NAME)
    }
  })
}

export async function dbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb()
  return idbGet<T>(db, STORE_NAME, key)
}

export async function dbSet(key: string, value: unknown): Promise<void> {
  const db = await openDb()
  return idbPut(db, STORE_NAME, value, key)
}

export async function dbDelete(key: string): Promise<void> {
  const db = await openDb()
  return idbDelete(db, STORE_NAME, key)
}

/**
 * Generate a new DSK (non-exportable AES-256-GCM key)
 */
export async function generateDsk(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // Non-exportable
    ['encrypt', 'decrypt']
  )
}

/**
 * Store DSK in IndexedDB
 */
export async function storeDsk(dsk: CryptoKey): Promise<void> {
  await dbSet(DSK_KEY, dsk)
}

/**
 * Load DSK from IndexedDB
 */
export async function loadDsk(): Promise<CryptoKey | null> {
  const dsk = await dbGet<CryptoKey>(DSK_KEY)
  return dsk ?? null
}

/**
 * Return an existing DSK or generate+store a new one when persistence is available.
 * Returns null if the browser does not support DSK persistence.
 */
export async function ensureDsk(): Promise<CryptoKey | null> {
  let dsk = await loadDsk()
  if (!dsk) {
    const { canPersistDsk } = await import('./dsk-capability')
    if (!(await canPersistDsk())) return null
    dsk = await generateDsk()
    await storeDsk(dsk)
  }
  return dsk
}
