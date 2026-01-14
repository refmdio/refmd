/**
 * Error Log Store
 *
 * Stores error logs in IndexedDB for debugging and troubleshooting.
 * Sensitive information is never stored.
 */

import type { ErrorCode, ErrorCategory, ErrorContext } from '../types/errors'

const DB_NAME = 'refmd-error-logs'
const DB_VERSION = 1
const STORE_NAME = 'logs'
const MAX_LOGS = 1000

/** Error log entry */
export interface ErrorLog {
  /** Unique ID */
  id: string
  /** Timestamp */
  timestamp: number
  /** Error code */
  code: ErrorCode
  /** Error category */
  category: ErrorCategory
  /** User-facing message (no sensitive data) */
  message: string
  /** Context (document/workspace IDs, operation name) */
  context?: ErrorContext
}

/**
 * Generate a unique ID
 */
function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`
}

/**
 * Open the IndexedDB database
 */
function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => {
      reject(new Error(`Failed to open error log database: ${request.error?.message}`))
    }

    request.onsuccess = () => {
      resolve(request.result)
    }

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result

      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' })
        // Index for querying by timestamp (for pruning old logs)
        store.createIndex('timestamp', 'timestamp', { unique: false })
        // Index for querying by code
        store.createIndex('code', 'code', { unique: false })
      }
    }
  })
}

/**
 * ErrorLogStore - manages error log storage in IndexedDB
 */
export class ErrorLogStore {
  private db: IDBDatabase | null = null

  /**
   * Initialize the store
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
   * Add an error log entry
   */
  async add(log: Omit<ErrorLog, 'id'>): Promise<void> {
    const db = await this.ensureDb()

    const entry: ErrorLog = {
      id: generateId(),
      ...log,
    }

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.add(entry)

      request.onerror = () => {
        reject(new Error(`Failed to add error log: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  /**
   * Get all error logs
   */
  async getAll(): Promise<ErrorLog[]> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.getAll()

      request.onerror = () => {
        reject(new Error(`Failed to get error logs: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        // Sort by timestamp descending (newest first)
        const logs = (request.result as ErrorLog[]).sort(
          (a, b) => b.timestamp - a.timestamp
        )
        resolve(logs)
      }
    })
  }

  /**
   * Get recent error logs
   */
  async getRecent(limit: number = 100): Promise<ErrorLog[]> {
    const all = await this.getAll()
    return all.slice(0, limit)
  }

  /**
   * Get log count
   */
  async count(): Promise<number> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.count()

      request.onerror = () => {
        reject(new Error(`Failed to count error logs: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve(request.result)
      }
    })
  }

  /**
   * Prune old logs to keep under MAX_LOGS
   */
  async prune(): Promise<number> {
    const db = await this.ensureDb()
    const currentCount = await this.count()

    if (currentCount <= MAX_LOGS) {
      return 0
    }

    const toDelete = currentCount - MAX_LOGS

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const index = store.index('timestamp')

      // Get oldest logs
      const request = index.openCursor()
      let deleted = 0

      request.onerror = () => {
        reject(new Error(`Failed to prune error logs: ${request.error?.message}`))
      }

      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result
        if (cursor && deleted < toDelete) {
          cursor.delete()
          deleted++
          cursor.continue()
        } else {
          resolve(deleted)
        }
      }
    })
  }

  /**
   * Clear all logs
   */
  async clear(): Promise<void> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.clear()

      request.onerror = () => {
        reject(new Error(`Failed to clear error logs: ${request.error?.message}`))
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
   * Delete the entire database
   */
  static async deleteDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(DB_NAME)

      request.onerror = () => {
        reject(new Error(`Failed to delete error log database: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }
}

// Singleton instance
let errorLogStoreInstance: ErrorLogStore | null = null

/**
 * Get the singleton ErrorLogStore instance
 */
export function getErrorLogStore(): ErrorLogStore {
  if (!errorLogStoreInstance) {
    errorLogStoreInstance = new ErrorLogStore()
  }
  return errorLogStoreInstance
}
