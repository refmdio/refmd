/**
 * Hook for generating Proof of Possession (PoP) headers
 *
 * Provides PoP header generation capability using the device context.
 * PoP headers are required for protected API endpoints per ADR-009.
 *
 * Uses server-issued challenges for replay attack prevention.
 */

import { useCallback } from 'react'
import { useAuthContext } from '@/shared/context/AuthContext'
import { getPopHeaders as fetchPopHeaders, type PopHeaders } from '@/shared/lib/crypto'
import { API_BASE } from '@/shared/api/client'

/**
 * Hook result for PoP operations
 */
export interface UsePopResult {
  /**
   * Whether device keys are available for PoP
   */
  hasDevice: boolean

  /**
   * Generate PoP headers for an API request
   * Returns undefined if device keys are not available
   * Now async because it fetches a server-issued challenge
   */
  getPopHeaders: () => Promise<PopHeaders | undefined>

  /**
   * Device ID if available
   */
  deviceId: string | undefined
}

/**
 * Hook for generating PoP headers
 *
 * Usage:
 * ```tsx
 * const { hasDevice, getPopHeaders } = usePop()
 *
 * if (hasDevice) {
 *   const headers = await getPopHeaders()
 *   // Add headers to API request
 * }
 * ```
 */
export function usePop(): UsePopResult {
  const { device } = useAuthContext()

  const getPopHeaders = useCallback(async (): Promise<PopHeaders | undefined> => {
    if (!device) {
      return undefined
    }

    return fetchPopHeaders(API_BASE, device.deviceId, device.deviceKeys.signingPrivateKey)
  }, [device])

  return {
    hasDevice: device !== null,
    getPopHeaders,
    deviceId: device?.deviceId,
  }
}
