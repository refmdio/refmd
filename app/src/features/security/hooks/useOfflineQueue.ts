/**
 * Offline Queue Hook
 *
 * Provides access to the offline queue with automatic processing on reconnect.
 */

import { useState, useEffect, useCallback, useRef } from 'react'

import {
  getOfflineQueue,
  type QueuedOperation,
  type OperationType,
} from '../lib/network/offline-queue'
import { withRetry } from '../lib/network/retry'

import { useNetworkStatus } from './useNetworkStatus'

const MAX_RETRY_COUNT = 5

export interface UseOfflineQueueOptions {
  /** Handler to process queued operations */
  processOperation?: (operation: QueuedOperation) => Promise<void>
  /** Whether to auto-process on reconnect */
  autoProcess?: boolean
}

export interface UseOfflineQueueResult {
  /** Number of pending operations */
  pendingCount: number
  /** List of pending operations */
  pendingOperations: QueuedOperation[]
  /** Whether queue is being processed */
  processing: boolean
  /** Add an operation to the queue */
  addToQueue: (
    type: OperationType,
    payload: string,
    metadata?: { documentId?: string; workspaceId?: string }
  ) => Promise<string>
  /** Manually process the queue */
  processQueue: () => Promise<void>
  /** Clear all pending operations */
  clearQueue: () => Promise<void>
  /** Refresh the queue state */
  refresh: () => Promise<void>
}

/**
 * Hook to manage the offline queue
 *
 * @param options - Configuration options
 * @returns Queue management functions and state
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { pendingCount, processing, addToQueue } = useOfflineQueue({
 *     processOperation: async (op) => {
 *       await sendToServer(op.payload)
 *     },
 *   })
 *
 *   return <div>{pendingCount} pending operations</div>
 * }
 * ```
 */
export function useOfflineQueue(
  options: UseOfflineQueueOptions = {}
): UseOfflineQueueResult {
  const { processOperation, autoProcess = true } = options

  const { isOnline } = useNetworkStatus()
  const [pendingOperations, setPendingOperations] = useState<QueuedOperation[]>([])
  const [processing, setProcessing] = useState(false)
  const processingRef = useRef(false)
  const prevOnlineRef = useRef(isOnline)

  // Refresh queue state
  const refresh = useCallback(async () => {
    try {
      const queue = getOfflineQueue()
      const operations = await queue.getAll()
      setPendingOperations(operations)
    } catch (error) {
      console.error('[useOfflineQueue] Failed to refresh queue:', error)
    }
  }, [])

  // Add to queue
  const addToQueue = useCallback(
    async (
      type: OperationType,
      payload: string,
      metadata?: { documentId?: string; workspaceId?: string }
    ): Promise<string> => {
      const queue = getOfflineQueue()
      const id = await queue.add({
        type,
        payload,
        documentId: metadata?.documentId,
        workspaceId: metadata?.workspaceId,
      })
      await refresh()
      return id
    },
    [refresh]
  )

  // Process queue
  const processQueue = useCallback(async () => {
    if (!processOperation || processingRef.current) return

    processingRef.current = true
    setProcessing(true)

    try {
      const queue = getOfflineQueue()
      const operations = await queue.getAll()

      for (const operation of operations) {
        // Skip operations that have exceeded retry limit
        if (operation.retryCount >= MAX_RETRY_COUNT) {
          console.warn(
            `[useOfflineQueue] Operation ${operation.id} exceeded max retries, removing`
          )
          await queue.remove(operation.id)
          continue
        }

        try {
          await withRetry(() => processOperation(operation), {
            maxRetries: 2,
            onRetry: (attempt) => {
              console.log(
                `[useOfflineQueue] Retrying operation ${operation.id}, attempt ${attempt}`
              )
            },
          })

          // Success - remove from queue
          await queue.remove(operation.id)
        } catch (error) {
          console.error(
            `[useOfflineQueue] Failed to process operation ${operation.id}:`,
            error
          )
          // Increment retry count
          await queue.incrementRetryCount(operation.id)
        }
      }

      await refresh()
    } finally {
      processingRef.current = false
      setProcessing(false)
    }
  }, [processOperation, refresh])

  // Clear queue
  const clearQueue = useCallback(async () => {
    const queue = getOfflineQueue()
    await queue.clear()
    await refresh()
  }, [refresh])

  // Initialize and refresh on mount
  useEffect(() => {
    const init = async () => {
      const queue = getOfflineQueue()
      await queue.initialize()
      await refresh()
    }
    init()
  }, [refresh])

  // Auto-process when coming back online
  useEffect(() => {
    if (autoProcess && !prevOnlineRef.current && isOnline && pendingOperations.length > 0) {
      processQueue()
    }
    prevOnlineRef.current = isOnline
  }, [isOnline, autoProcess, pendingOperations.length, processQueue])

  return {
    pendingCount: pendingOperations.length,
    pendingOperations,
    processing,
    addToQueue,
    processQueue,
    clearQueue,
    refresh,
  }
}
