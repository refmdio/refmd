/**
 * Device Registration Approval Hook
 *
 * Handles the approval flow when an existing device approves a new device.
 * Extracts all crypto logic from the device-register route.
 *
 * Responsibilities:
 * - TOFU verification of the UMK sender device
 * - Delegates UMK decryption + key storage to device-registration-service
 * - Auth/Device state setup
 * - Trust transfer delegation
 * - Key change warning dialog management
 */

import { useCallback, useRef } from 'react'
import { useLatest, useKeyChangeFlow } from '@/shared/hooks'
import { base64UrlDecode, evaluateDeviceTofu, dispatchTofuDecision } from '@/shared/lib/crypto'
import { initializeDeviceState } from '@/shared/lib/device-init'
import { deviceApi } from '@/shared/api'
import type { AuthState, DeviceState } from '@/shared/model/auth-types'
import { buildAuthState, buildDeviceState } from '@/shared/model/session-hydration'
import type { DeviceRegistrationState } from './useDevice'
import type { UseTrustTransferReturn } from './useTrustTransfer'
import { completeDeviceRegistration } from '../lib/device-registration-service'

interface UseDeviceRegistrationApprovalParams {
  auth: AuthState | null
  deviceState: DeviceRegistrationState
  setFullSession: (auth: AuthState, device: DeviceState) => void
  executeTrustTransfer: UseTrustTransferReturn['executeTrustTransfer']
  onNavigate: () => void
  onError: (msg: string) => void
}

export function useDeviceRegistrationApproval({
  auth,
  deviceState,
  setFullSession,
  executeTrustTransfer,
  onNavigate,
  onError,
}: UseDeviceRegistrationApprovalParams) {
  // Refs to avoid stale closures in SSE event handler
  const stateRef = useLatest(deviceState)
  const authRef = useLatest(auth)

  // Store pending deviceId for re-calling handleApproval after trust
  const pendingDeviceIdRef = useRef<string | null>(null)
  const handleApprovalRef = useRef<((deviceId: string) => Promise<void>) | null>(null)

  const keyChange = useKeyChangeFlow({
    afterTrust: async () => {
      const deviceId = pendingDeviceIdRef.current
      if (deviceId) {
        pendingDeviceIdRef.current = null
        handleApprovalRef.current?.(deviceId)
      }
    },
    onBlock: (_item) => {
      pendingDeviceIdRef.current = null
      onError('Device approval cancelled due to key change concerns.')
    },
    onCancel: (_remaining) => {
      pendingDeviceIdRef.current = null
      onError('Device approval paused. Verify the sender device before continuing.')
    },
  })

  const handleApproval = useCallback(async (deviceId: string) => {
    const currentState = stateRef.current
    const currentAuth = authRef.current

    if (!currentState.deviceKeyPair || !currentAuth) {
      onError('Missing device keys or auth state')
      return
    }

    try {
      // Phase 1: Initialize device state (PoP + DSK + key storage)
      const dsk = await initializeDeviceState({
        deviceId,
        deviceKeyPair: currentState.deviceKeyPair,
        userId: currentAuth.userId,
      })

      // Phase 2: Fetch UMK + TOFU verification
      const umkData = await deviceApi.getDeviceUmk(deviceId)

      const tofuDecision = await evaluateDeviceTofu(
        currentAuth.userId,
        umkData.sender_device_id,
        umkData.sender_signing_public_key,
        umkData.sender_ecdh_public_key
      )

      if (dispatchTofuDecision(tofuDecision, `Device ${umkData.sender_device_id.slice(0, 8)}...`, {
        onAbort: (reason) => { throw new Error(reason) },
        onKeyChanged: (item) => { pendingDeviceIdRef.current = deviceId; keyChange.push(item) },
      })) return // Wait for user confirmation

      // Phase 3: Complete registration (UMK decrypt + store + identity keys)
      const { umk, identityKeys } = await completeDeviceRegistration({
        umkData,
        senderEcdhPublicKey: base64UrlDecode(umkData.sender_ecdh_public_key),
        deviceKeyPair: currentState.deviceKeyPair,
        userId: currentAuth.userId,
        deviceId,
        dsk,
      })

      // Phase 4: Set full session (auth + device) atomically
      setFullSession(
        buildAuthState({
          userId: currentAuth.userId,
          email: currentAuth.email,
          expiresAt: currentAuth.expiresAt,
          umk,
          identityKeys,
        }),
        buildDeviceState({ deviceId, deviceKeys: currentState.deviceKeyPair }),
      )

      // Phase 5: Trust transfer + navigate
      const trustResult = await executeTrustTransfer({
        deviceId,
        ecdhPrivateKey: currentState.deviceKeyPair.ecdhPrivateKey,
        userId: currentAuth.userId,
      })
      if (trustResult.status === 'pending') return
      if (trustResult.status === 'security_abort') {
        onError(trustResult.message)
        return
      }

      onNavigate()
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Failed to complete device setup')
    }
  }, [setFullSession, executeTrustTransfer, onNavigate, onError, keyChange.push])

  handleApprovalRef.current = handleApproval

  return {
    handleApproval,
    keyChangeDialogProps: keyChange.dialogProps,
  }
}
