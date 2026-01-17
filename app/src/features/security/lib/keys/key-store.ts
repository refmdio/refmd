/**
 * E2EE Key Store
 *
 * Stores encrypted keys in IndexedDB.
 * UMK storage depends on user's "Remember Me" preference:
 * - rememberMe=true: stored in IndexedDB (persists across sessions)
 * - rememberMe=false: stored in sessionStorage (cleared on tab close)
 */

import type { Argon2Params, Pbkdf2Params } from '../types'

const DB_NAME = 'refmd-e2ee'
const DB_VERSION = 2
const STORE_NAME = 'keys'
const KEYS_ID = 'user-keys'
const SESSION_ID = 'session-umk'
const SESSION_STORAGE_UMK_KEY = 'refmd-e2ee-session-umk'

/** Stored key data structure */
export interface StoredKeys {
  /** ECDH private key encrypted with UMK */
  encryptedEcdhPrivateKey: Uint8Array
  /** Nonce for ECDH private key encryption */
  encryptedEcdhPrivateKeyNonce: Uint8Array
  /** Ed25519 signing private key encrypted with UMK */
  encryptedSigningPrivateKey: Uint8Array
  /** Nonce for signing private key encryption */
  encryptedSigningPrivateKeyNonce: Uint8Array
  /** ECDH public key (unencrypted) */
  ecdhPublicKey: Uint8Array
  /** Ed25519 signing public key (unencrypted) */
  signingPublicKey: Uint8Array
  /** Salt used for passphrase derivation */
  salt: Uint8Array
  /** KDF type used */
  kdf: 'argon2id' | 'pbkdf2'
  /** KDF parameters */
  kdfParams: Argon2Params | Pbkdf2Params
  /** When the keys were created */
  createdAt: number
}

/** Serializable format for IndexedDB */
interface SerializedStoredKeys {
  encryptedEcdhPrivateKey: number[]
  encryptedEcdhPrivateKeyNonce: number[]
  encryptedSigningPrivateKey: number[]
  encryptedSigningPrivateKeyNonce: number[]
  ecdhPublicKey: number[]
  signingPublicKey: number[]
  salt: number[]
  kdf: 'argon2id' | 'pbkdf2'
  kdfParams: Argon2Params | Pbkdf2Params
  createdAt: number
}

/**
 * Open the IndexedDB database
 */
function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => {
      reject(new Error(`Failed to open database: ${request.error?.message}`))
    }

    request.onsuccess = () => {
      resolve(request.result)
    }

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result

      // Create the keys store if it doesn't exist
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' })
      }
    }
  })
}

/**
 * Serialize StoredKeys to a format safe for IndexedDB
 */
function serializeKeys(keys: StoredKeys): SerializedStoredKeys {
  return {
    encryptedEcdhPrivateKey: Array.from(keys.encryptedEcdhPrivateKey),
    encryptedEcdhPrivateKeyNonce: Array.from(keys.encryptedEcdhPrivateKeyNonce),
    encryptedSigningPrivateKey: Array.from(keys.encryptedSigningPrivateKey),
    encryptedSigningPrivateKeyNonce: Array.from(keys.encryptedSigningPrivateKeyNonce),
    ecdhPublicKey: Array.from(keys.ecdhPublicKey),
    signingPublicKey: Array.from(keys.signingPublicKey),
    salt: Array.from(keys.salt),
    kdf: keys.kdf,
    kdfParams: keys.kdfParams,
    createdAt: keys.createdAt,
  }
}

/**
 * Deserialize keys from IndexedDB format
 */
function deserializeKeys(data: SerializedStoredKeys): StoredKeys {
  return {
    encryptedEcdhPrivateKey: new Uint8Array(data.encryptedEcdhPrivateKey),
    encryptedEcdhPrivateKeyNonce: new Uint8Array(data.encryptedEcdhPrivateKeyNonce),
    encryptedSigningPrivateKey: new Uint8Array(data.encryptedSigningPrivateKey),
    encryptedSigningPrivateKeyNonce: new Uint8Array(data.encryptedSigningPrivateKeyNonce),
    ecdhPublicKey: new Uint8Array(data.ecdhPublicKey),
    signingPublicKey: new Uint8Array(data.signingPublicKey),
    salt: new Uint8Array(data.salt),
    kdf: data.kdf,
    kdfParams: data.kdfParams,
    createdAt: data.createdAt,
  }
}

/**
 * KeyStore - manages encrypted key storage in IndexedDB
 */
export class KeyStore {
  private db: IDBDatabase | null = null

  /**
   * Initialize the key store
   */
  async initialize(): Promise<void> {
    if (this.db) return
    this.db = await openDatabase()
  }

  /**
   * Ensure database is initialized
   */
  private async ensureDb(): Promise<IDBDatabase> {
    if (!this.db) {
      await this.initialize()
    }
    return this.db!
  }

  /**
   * Save encrypted keys to IndexedDB
   */
  async saveKeys(keys: StoredKeys): Promise<void> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)

      const data = {
        id: KEYS_ID,
        ...serializeKeys(keys),
      }

      const request = store.put(data)

      request.onerror = () => {
        reject(new Error(`Failed to save keys: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  /**
   * Load encrypted keys from IndexedDB
   */
  async loadKeys(): Promise<StoredKeys | null> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.get(KEYS_ID)

      request.onerror = () => {
        reject(new Error(`Failed to load keys: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        if (!request.result) {
          resolve(null)
          return
        }

        // Remove the id field before deserializing
         
        const { id, ...data } = request.result
        resolve(deserializeKeys(data as SerializedStoredKeys))
      }
    })
  }

  /**
   * Check if keys exist in IndexedDB
   */
  async hasKeys(): Promise<boolean> {
    const keys = await this.loadKeys()
    return keys !== null
  }

  /**
   * Clear all keys from IndexedDB
   */
  async clear(): Promise<void> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.delete(KEYS_ID)

      request.onerror = () => {
        reject(new Error(`Failed to clear keys: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  /**
   * Save session UMK for session continuity.
   *
   * @param umk - The User Master Key
   * @param options - Storage options
   * @param options.rememberMe - If true, store in IndexedDB (persists across sessions).
   *                             If false, store in sessionStorage (cleared on tab close).
   */
  async saveSessionUmk(umk: Uint8Array, options?: { rememberMe?: boolean }): Promise<void> {
    const rememberMe = options?.rememberMe ?? false

    if (rememberMe) {
      // Store in IndexedDB for persistent storage
      const db = await this.ensureDb()

      // Clear sessionStorage to avoid stale data being loaded first
      try {
        sessionStorage.removeItem(SESSION_STORAGE_UMK_KEY)
      } catch {
        // sessionStorage not available
      }

      return new Promise((resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, 'readwrite')
        const store = transaction.objectStore(STORE_NAME)

        const data = {
          id: SESSION_ID,
          umk: Array.from(umk),
          savedAt: Date.now(),
        }

        const request = store.put(data)

        request.onerror = () => {
          reject(new Error(`Failed to save session UMK: ${request.error?.message}`))
        }

        request.onsuccess = () => {
          resolve()
        }
      })
    } else {
      // Store in sessionStorage for session-only storage
      try {
        const encoded = btoa(String.fromCharCode(...umk))
        sessionStorage.setItem(SESSION_STORAGE_UMK_KEY, encoded)
      } catch {
        throw new Error('Failed to save session UMK to sessionStorage')
      }

      // Clear any existing UMK from IndexedDB to ensure clean state
      // This prevents old remembered sessions from being used
      await this.clearIndexedDbUmk()
    }
  }

  /**
   * Clear UMK from IndexedDB only.
   * Used internally when rememberMe is false to ensure clean state.
   */
  private async clearIndexedDbUmk(): Promise<void> {
    const db = await this.ensureDb()

    return new Promise((resolve) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.delete(SESSION_ID)

      request.onerror = () => {
        // Ignore errors - this is a best-effort cleanup
        resolve()
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  /**
   * Load session UMK from storage.
   * Checks both IndexedDB (for rememberMe=true) and sessionStorage (for rememberMe=false).
   * Returns null if no session UMK is stored.
   */
  async loadSessionUmk(): Promise<Uint8Array | null> {
    // First, try sessionStorage (for current session)
    try {
      const encoded = sessionStorage.getItem(SESSION_STORAGE_UMK_KEY)
      if (encoded) {
        const decoded = atob(encoded)
        const umk = new Uint8Array(decoded.length)
        for (let i = 0; i < decoded.length; i++) {
          umk[i] = decoded.charCodeAt(i)
        }
        return umk
      }
    } catch {
      // sessionStorage not available or invalid data
    }

    // Then, try IndexedDB (for remembered sessions)
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.get(SESSION_ID)

      request.onerror = () => {
        reject(new Error(`Failed to load session UMK: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        if (!request.result || !request.result.umk) {
          resolve(null)
          return
        }

        resolve(new Uint8Array(request.result.umk))
      }
    })
  }

  /**
   * Clear session UMK from all storage locations.
   * Called on logout or manual lock.
   */
  async clearSessionUmk(): Promise<void> {
    // Clear from sessionStorage
    try {
      sessionStorage.removeItem(SESSION_STORAGE_UMK_KEY)
    } catch {
      // sessionStorage not available
    }

    // Clear from IndexedDB
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.delete(SESSION_ID)

      request.onerror = () => {
        reject(new Error(`Failed to clear session UMK: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  /**
   * Close the database connection
   */
  close(): void {
    if (this.db) {
      this.db.close()
      this.db = null
    }
  }

  /**
   * Delete the entire database (for testing/reset)
   */
  static async deleteDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(DB_NAME)

      request.onerror = () => {
        reject(new Error(`Failed to delete database: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }
}

// Singleton instance
let keyStoreInstance: KeyStore | null = null

/**
 * Get the singleton KeyStore instance
 */
export function getKeyStore(): KeyStore {
  if (!keyStoreInstance) {
    keyStoreInstance = new KeyStore()
  }
  return keyStoreInstance
}
