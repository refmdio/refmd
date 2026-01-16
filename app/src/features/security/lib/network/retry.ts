/**
 * Retry Logic with Exponential Backoff
 *
 * Provides retry functionality for network operations.
 */

import { CryptoError, ERROR_CODES, isCryptoError } from '../types/errors'

const DEFAULT_MAX_RETRIES = 3
const DEFAULT_RETRY_DELAYS = [1000, 5000, 15000] // 1s, 5s, 15s

export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number
  /** Delay between retries in ms (default: [1000, 5000, 15000]) */
  retryDelays?: number[]
  /** Called on each retry attempt */
  onRetry?: (attempt: number, error: Error) => void
  /** Custom function to determine if error is retryable */
  shouldRetry?: (error: Error) => boolean
}

/**
 * Check if an error is retryable
 */
function isRetryableError(error: unknown): boolean {
  if (isCryptoError(error)) {
    return (
      error.code === ERROR_CODES.NETWORK_FAILED ||
      error.code === ERROR_CODES.SYNC_TIMEOUT ||
      error.code === ERROR_CODES.SERVER_ERROR
    )
  }

  // Check for standard network errors
  if (error instanceof Error) {
    const message = error.message.toLowerCase()
    return (
      message.includes('network') ||
      message.includes('fetch') ||
      message.includes('timeout') ||
      message.includes('connection')
    )
  }

  return false
}

/**
 * Delay for a specified number of milliseconds
 */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Execute a function with retry logic
 *
 * @param fn - The async function to execute
 * @param options - Retry options
 * @returns The result of the function
 * @throws The last error if all retries fail
 *
 * @example
 * ```ts
 * const result = await withRetry(
 *   () => fetchData(),
 *   { onRetry: (attempt) => console.log(`Retry ${attempt}`) }
 * )
 * ```
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: RetryOptions
): Promise<T> {
  const {
    maxRetries = DEFAULT_MAX_RETRIES,
    retryDelays = DEFAULT_RETRY_DELAYS,
    onRetry,
    shouldRetry = isRetryableError,
  } = options ?? {}

  let lastError: Error | undefined

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))

      const isRetryable = shouldRetry(lastError)
      const hasMoreAttempts = attempt < maxRetries

      if (isRetryable && hasMoreAttempts) {
        const delayMs = retryDelays[attempt] ?? retryDelays[retryDelays.length - 1]
        onRetry?.(attempt + 1, lastError)
        await delay(delayMs)
        continue
      }

      // Not retryable or no more attempts - throw
      throw lastError
    }
  }

  // Should never reach here, but TypeScript needs this
  throw lastError ?? new Error('Unknown error')
}

/**
 * Create a retryable version of an async function
 *
 * @param fn - The async function to wrap
 * @param options - Retry options
 * @returns A wrapped function with retry logic
 *
 * @example
 * ```ts
 * const retryableFetch = makeRetryable(fetchData, { maxRetries: 5 })
 * const result = await retryableFetch()
 * ```
 */
export function makeRetryable<T extends unknown[], R>(
  fn: (...args: T) => Promise<R>,
  options?: RetryOptions
): (...args: T) => Promise<R> {
  return (...args: T) => withRetry(() => fn(...args), options)
}

/**
 * Wrap a network error as a CryptoError
 */
export function wrapNetworkError(error: unknown): CryptoError {
  if (isCryptoError(error)) {
    return error
  }

  const message = error instanceof Error ? error.message : 'Network error'
  return new CryptoError(ERROR_CODES.NETWORK_FAILED, message, {
    cause: error instanceof Error ? error : undefined,
  })
}
