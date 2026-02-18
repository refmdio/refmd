/**
 * Device Registration Hook
 *
 * Handles multi-device registration flow:
 * 1. Generate device key pair
 * 2. Create pending device on server
 * 3. Display/verify SAS
 * 4. Approve device with identity signature
 * 5. Receive UMK from existing device
 */

import { useState, useCallback } from 'react'
import { deviceApi } from '@/shared/api'
import {
  generateDeviceKeyPair,
  base64UrlDecode,
  generateSasEmojis,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'
import { buildPendingDevicePayload } from '@/shared/lib/pending-device-payload'
import type { DeviceType } from '@/shared/lib/device'

export type DeviceRegistrationStep =
  | 'idle'
  | 'generating-keys'
  | 'creating-pending'
  | 'waiting-for-approval'
  | 'error'

export interface DeviceRegistrationState {
  step: DeviceRegistrationStep
  error: string | null
  pendingDeviceId: string | null
  sasEmojis: string | null
  deviceKeyPair: DeviceKeyPair | null
}

export interface UseDeviceReturn {
  /** Current registration state */
  state: DeviceRegistrationState

  /** Start new device registration (on new device) */
  startRegistration: (deviceName: string, deviceType: DeviceType) => Promise<void>

  /** Reset state */
  reset: () => void
}

const initialState: DeviceRegistrationState = {
  step: 'idle',
  error: null,
  pendingDeviceId: null,
  sasEmojis: null,
  deviceKeyPair: null,
}

/**
 * Hook for device registration and management
 */
export function useDevice(): UseDeviceReturn {
  const [state, setState] = useState<DeviceRegistrationState>(initialState)

  const reset = useCallback(() => {
    setState(initialState)
  }, [])

  /**
   * Start device registration on a new device
   */
  const startRegistration = useCallback(
    async (deviceName: string, deviceType: DeviceType) => {
      try {
        setState((s) => ({ ...s, step: 'generating-keys', error: null }))

        // Generate device key pair
        const deviceKeyPair = generateDeviceKeyPair()
        const { payload, clientNonce } = buildPendingDevicePayload(deviceKeyPair, deviceName, deviceType)

        setState((s) => ({
          ...s,
          step: 'creating-pending',
          deviceKeyPair,
        }))

        // Create pending device on server
        const response = await deviceApi.createPendingDevice(payload)

        // Calculate SAS on client side using identity public key from response
        const identitySigningPk = base64UrlDecode(response.identity_signing_public_key)
        const sasEmojis = generateSasEmojis(
          identitySigningPk,
          deviceKeyPair.signingPublicKey,
          deviceKeyPair.ecdhPublicKey,
          clientNonce
        )

        setState((s) => ({
          ...s,
          step: 'waiting-for-approval',
          pendingDeviceId: response.id,
          sasEmojis,
        }))
      } catch (error) {
        setState((s) => ({
          ...s,
          step: 'error',
          error: error instanceof Error ? error.message : 'Failed to start registration',
        }))
        throw error
      }
    },
    []
  )

  return {
    state,
    startRegistration,
    reset,
  }
}
