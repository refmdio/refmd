/**
 * Error Log Module
 *
 * Provides error logging to IndexedDB for debugging.
 */

export {
  ErrorLogStore,
  getErrorLogStore,
  type ErrorLog,
} from './error-log-store'

export {
  logError,
  logAndThrow,
  getRecentErrors,
  clearErrorLogs,
} from './log-error'
