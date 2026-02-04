/**
 * Hook for generating Proof of Possession (PoP) headers
 *
 * Provides PoP header generation capability using the device context.
 * PoP headers are required for protected API endpoints per ADR-009.
 */

import { useCallback } from 'react'
import { useAuthContext } from '@/shared/context/AuthContext'
import { generatePopHeaders, type PopHeaders } from '@/shared/lib/crypto'

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
   */
  getPopHeaders: () => PopHeaders | undefined

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
 *   const headers = getPopHeaders()
 *   // Add headers to API request
 * }
 * ```
 */
export function usePop(): UsePopResult {
  const { device } = useAuthContext()

  const getPopHeaders = useCallback((): PopHeaders | undefined => {
    if (!device) {
      return undefined
    }

    return generatePopHeaders(device.deviceId, device.deviceKeys.signingPrivateKey)
  }, [device])

  return {
    hasDevice: device !== null,
    getPopHeaders,
    deviceId: device?.deviceId,
  }
}
