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
  generateClientNonce,
  base64UrlEncode,
  base64UrlDecode,
  generateSasEmojis,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'

export type DeviceRegistrationStep =
  | 'idle'
  | 'generating-keys'
  | 'creating-pending'
  | 'waiting-for-approval'
  | 'approved'
  | 'error'

export interface DeviceRegistrationState {
  step: DeviceRegistrationStep
  error: string | null
  pendingDeviceId: string | null
  sasEmojis: string | null
  deviceKeyPair: DeviceKeyPair | null
  clientNonce: Uint8Array | null
}

export interface UseDeviceReturn {
  /** Current registration state */
  state: DeviceRegistrationState

  /** Start new device registration (on new device) */
  startRegistration: (deviceName: string, deviceType: 'browser' | 'desktop' | 'mobile') => Promise<void>

  /** Get SAS emojis for existing device verification (calculates locally) */
  getSas: (pendingDeviceId: string, identitySigningPublicKey: Uint8Array) => Promise<string>

  /** List all user's devices */
  listDevices: () => Promise<Awaited<ReturnType<typeof deviceApi.listDevices>>>

  /** List pending devices awaiting approval */
  listPendingDevices: () => Promise<Awaited<ReturnType<typeof deviceApi.listPendingDevices>>>

  /** Reset state */
  reset: () => void
}

const initialState: DeviceRegistrationState = {
  step: 'idle',
  error: null,
  pendingDeviceId: null,
  sasEmojis: null,
  deviceKeyPair: null,
  clientNonce: null,
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
    async (deviceName: string, deviceType: 'browser' | 'desktop' | 'mobile') => {
      try {
        setState((s) => ({ ...s, step: 'generating-keys', error: null }))

        // Generate device key pair
        const deviceKeyPair = generateDeviceKeyPair()
        const clientNonce = generateClientNonce()

        setState((s) => ({
          ...s,
          step: 'creating-pending',
          deviceKeyPair,
          clientNonce,
        }))

        // Create pending device on server
        const response = await deviceApi.createPendingDevice({
          device_name: deviceName,
          device_type: deviceType,
          ecdh_public_key: base64UrlEncode(deviceKeyPair.ecdhPublicKey),
          signing_public_key: base64UrlEncode(deviceKeyPair.signingPublicKey),
          client_nonce: base64UrlEncode(clientNonce),
        })

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

  /**
   * Get SAS emojis for a pending device (called from existing device)
   *
   * Fetches pending device's public keys from server and calculates SAS locally
   * using the existing device's identity signing public key.
   *
   * @param pendingDeviceId - ID of the pending device
   * @param identitySigningPublicKey - Existing device's identity signing public key
   * @returns SAS emoji string calculated locally
   */
  const getSas = useCallback(
    async (pendingDeviceId: string, identitySigningPublicKey: Uint8Array): Promise<string> => {
      // Fetch pending device's public keys from server
      const response = await deviceApi.getSas(pendingDeviceId)

      // Decode the pending device's keys
      const deviceSigningPk = base64UrlDecode(response.device_signing_public_key)
      const deviceEcdhPk = base64UrlDecode(response.device_ecdh_public_key)
      const clientNonce = base64UrlDecode(response.client_nonce)

      // Calculate SAS locally using our identity signing public key
      return generateSasEmojis(identitySigningPublicKey, deviceSigningPk, deviceEcdhPk, clientNonce)
    },
    []
  )

  /**
   * List all devices for the current user
   */
  const listDevices = useCallback(async () => {
    return await deviceApi.listDevices()
  }, [])

  /**
   * List pending devices awaiting approval
   */
  const listPendingDevices = useCallback(async () => {
    return await deviceApi.listPendingDevices()
  }, [])


  return {
    state,
    startRegistration,
    getSas,
    listDevices,
    listPendingDevices,
    reset,
  }
}
