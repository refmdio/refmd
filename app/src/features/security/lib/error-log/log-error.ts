/**
 * Error Logging
 *
 * Logs errors to IndexedDB with sensitive information filtered out.
 * Never sends error data to the server.
 */

import { type CryptoError, type ErrorContext } from '@/shared/types/security'

import { getErrorLogStore, type ErrorLog } from './error-log-store'

/**
 * Sanitize error context to remove any potentially sensitive data
 */
function sanitizeContext(context?: ErrorContext): ErrorContext | undefined {
  if (!context) return undefined

  // Only keep safe fields (IDs and operation names)
  const safe: ErrorContext = {}

  if (context.documentId) {
    safe.documentId = context.documentId
  }
  if (context.workspaceId) {
    safe.workspaceId = context.workspaceId
  }
  if (context.operation) {
    safe.operation = context.operation
  }

  return Object.keys(safe).length > 0 ? safe : undefined
}

/**
 * Log a CryptoError to IndexedDB
 *
 * Sensitive information (keys, passphrases, content) is never logged.
 * Only error codes, user-facing messages, and safe context are stored.
 */
export async function logError(error: CryptoError): Promise<void> {
  try {
    const store = getErrorLogStore()

    const logEntry: Omit<ErrorLog, 'id'> = {
      timestamp: Date.now(),
      code: error.code,
      category: error.category,
      message: error.getUserMessage(),
      context: sanitizeContext(error.context),
    }

    await store.add(logEntry)

    // Prune old logs to prevent unbounded growth
    await store.prune()

    // In development, also log to console
    if (process.env.NODE_ENV === 'development') {
      console.error('[CryptoError]', {
        code: error.code,
        category: error.category,
        message: error.message,
        context: error.context,
      })
    }
  } catch (logStoreError) {
    // Don't throw if logging fails - just log to console in dev
    if (process.env.NODE_ENV === 'development') {
      console.error('[CryptoError] Failed to log error:', logStoreError)
      console.error('[CryptoError] Original error:', error)
    }
  }
}

/**
 * Log an error and re-throw it
 *
 * Useful for logging errors in catch blocks without swallowing them.
 */
export async function logAndThrow(error: CryptoError): Promise<never> {
  await logError(error)
  throw error
}

/**
 * Get recent error logs for debugging
 *
 * Only available in the browser.
 */
export async function getRecentErrors(limit: number = 100): Promise<ErrorLog[]> {
  const store = getErrorLogStore()
  return store.getRecent(limit)
}

/**
 * Clear all error logs
 */
export async function clearErrorLogs(): Promise<void> {
  const store = getErrorLogStore()
  return store.clear()
}
