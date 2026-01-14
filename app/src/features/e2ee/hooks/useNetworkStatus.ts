/**
 * Network Status Hook
 *
 * Provides reactive network status monitoring.
 */

import { useState, useEffect, useCallback } from 'react'

export interface NetworkStatus {
  /** Whether the browser is online */
  isOnline: boolean
  /** Timestamp of last status change */
  lastChanged: number | null
}

/**
 * Hook to monitor network connectivity status
 *
 * @returns Network status object
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { isOnline } = useNetworkStatus()
 *   return <div>{isOnline ? 'Online' : 'Offline'}</div>
 * }
 * ```
 */
export function useNetworkStatus(): NetworkStatus {
  const [status, setStatus] = useState<NetworkStatus>(() => ({
    isOnline: typeof navigator !== 'undefined' ? navigator.onLine : true,
    lastChanged: null,
  }))

  const handleOnline = useCallback(() => {
    setStatus({
      isOnline: true,
      lastChanged: Date.now(),
    })
  }, [])

  const handleOffline = useCallback(() => {
    setStatus({
      isOnline: false,
      lastChanged: Date.now(),
    })
  }, [])

  useEffect(() => {
    // Update initial status (handles SSR case)
    if (typeof navigator !== 'undefined') {
      setStatus((prev) => ({
        ...prev,
        isOnline: navigator.onLine,
      }))
    }

    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [handleOnline, handleOffline])

  return status
}
