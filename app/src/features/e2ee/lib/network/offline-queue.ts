/**
 * Offline Queue
 *
 * Stores pending operations when offline and processes them when online.
 * Only encrypted data is stored - never plaintext.
 */

const DB_NAME = 'refmd-offline-queue'
const DB_VERSION = 1
const STORE_NAME = 'queue'

export type OperationType = 'sync' | 'upload' | 'key_refresh'

export interface QueuedOperation {
  /** Unique ID */
  id: string
  /** Operation type */
  type: OperationType
  /** Encrypted payload (never plaintext) */
  payload: string
  /** Associated document ID */
  documentId?: string
  /** Associated workspace ID */
  workspaceId?: string
  /** When the operation was queued */
  createdAt: number
  /** Number of retry attempts */
  retryCount: number
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
      reject(new Error(`Failed to open offline queue database: ${request.error?.message}`))
    }

    request.onsuccess = () => {
      resolve(request.result)
    }

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result

      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' })
        store.createIndex('type', 'type', { unique: false })
        store.createIndex('createdAt', 'createdAt', { unique: false })
      }
    }
  })
}

/**
 * OfflineQueue - manages pending operations when offline
 */
export class OfflineQueue {
  private db: IDBDatabase | null = null

  /**
   * Initialize the queue
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
   * Add an operation to the queue
   */
  async add(
    operation: Omit<QueuedOperation, 'id' | 'createdAt' | 'retryCount'>
  ): Promise<string> {
    const db = await this.ensureDb()

    const entry: QueuedOperation = {
      id: generateId(),
      createdAt: Date.now(),
      retryCount: 0,
      ...operation,
    }

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.add(entry)

      request.onerror = () => {
        reject(new Error(`Failed to add to offline queue: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve(entry.id)
      }
    })
  }

  /**
   * Get all queued operations
   */
  async getAll(): Promise<QueuedOperation[]> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.getAll()

      request.onerror = () => {
        reject(new Error(`Failed to get offline queue: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        // Sort by createdAt ascending (oldest first)
        const operations = (request.result as QueuedOperation[]).sort(
          (a, b) => a.createdAt - b.createdAt
        )
        resolve(operations)
      }
    })
  }

  /**
   * Get operations by type
   */
  async getByType(type: OperationType): Promise<QueuedOperation[]> {
    const all = await this.getAll()
    return all.filter((op) => op.type === type)
  }

  /**
   * Get queue count
   */
  async count(): Promise<number> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.count()

      request.onerror = () => {
        reject(new Error(`Failed to count offline queue: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve(request.result)
      }
    })
  }

  /**
   * Remove an operation from the queue
   */
  async remove(id: string): Promise<void> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.delete(id)

      request.onerror = () => {
        reject(new Error(`Failed to remove from offline queue: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  /**
   * Increment retry count for an operation
   */
  async incrementRetryCount(id: string): Promise<void> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const getRequest = store.get(id)

      getRequest.onerror = () => {
        reject(new Error(`Failed to get operation: ${getRequest.error?.message}`))
      }

      getRequest.onsuccess = () => {
        const operation = getRequest.result as QueuedOperation | undefined
        if (!operation) {
          resolve()
          return
        }

        operation.retryCount++
        const putRequest = store.put(operation)

        putRequest.onerror = () => {
          reject(new Error(`Failed to update operation: ${putRequest.error?.message}`))
        }

        putRequest.onsuccess = () => {
          resolve()
        }
      }
    })
  }

  /**
   * Clear all operations
   */
  async clear(): Promise<void> {
    const db = await this.ensureDb()

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.clear()

      request.onerror = () => {
        reject(new Error(`Failed to clear offline queue: ${request.error?.message}`))
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
        reject(new Error(`Failed to delete offline queue database: ${request.error?.message}`))
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }
}

// Singleton instance
let offlineQueueInstance: OfflineQueue | null = null

/**
 * Get the singleton OfflineQueue instance
 */
export function getOfflineQueue(): OfflineQueue {
  if (!offlineQueueInstance) {
    offlineQueueInstance = new OfflineQueue()
  }
  return offlineQueueInstance
}
