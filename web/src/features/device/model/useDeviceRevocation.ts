/**
 * Device Revocation Hook
 *
 * Handles device revocation API call and anti-rollback pinning.
 * Delegates all KEK/DEK rotation and TOFU verification to useKekRotation.
 */

import { useCallback } from 'react'
import { useLatest, type KeyChangeWarningDialogProps } from '@/shared/hooks'
import { deviceApi } from '@/shared/api'
import {
  base64UrlEncode,
  sign,
  buildSignatureMessage,
  SIGNATURE_ACTION,
} from '@/shared/lib/crypto'
import { pinRevocation } from '@/shared/lib/anti-rollback'
import { useKekRotation } from './useKekRotation'
import type { components } from '@/shared/api'
import type { AuthInfo, CurrentDeviceInfo } from './types'

type WorkspaceDocumentsForRotation = components['schemas']['WorkspaceDocumentsForRotationResponse']

export type RevocationMode = 'security' | 'retire'

export interface UseDeviceRevocationReturn {
  revokeDevice: (deviceId: string, mode: RevocationMode) => Promise<void>
  rotatingKek: boolean
  keyChangeDialogProps: KeyChangeWarningDialogProps | null
}

export function useDeviceRevocation(
  auth: AuthInfo | null,
  currentDevice: CurrentDeviceInfo | null,
  onDevicesChanged: () => Promise<void>,
  onError: (message: string) => void
): UseDeviceRevocationReturn {
  const authRef = useLatest(auth)
  const deviceRef = useLatest(currentDevice)
  const onDevicesChangedRef = useLatest(onDevicesChanged)
  const onErrorRef = useLatest(onError)

  // KEK rotation (handles all TOFU verification and dialog management)
  const kekRotation = useKekRotation(auth, currentDevice, onDevicesChanged, onError)

  const revokeDevice = useCallback(async (deviceId: string, mode: RevocationMode = 'security') => {
    const currentAuth = authRef.current
    const currentDev = deviceRef.current
    if (!currentAuth || !currentDev) {
      onErrorRef.current('Authentication required')
      return
    }

    try {
      const revokedAt = Date.now()
      const message = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_REVOCATION, {
        user_id: currentAuth.userId,
        device_id: deviceId,
        revocation_mode: mode,
        revoked_at: revokedAt,
        revoked_by_device_id: currentDev.deviceId,
      })

      if (!currentAuth.identityKeys) {
        throw new Error('Identity keys not available')
      }
      const signature = sign(message, currentAuth.identityKeys.signingPrivate)

      const response = await deviceApi.revokeDevice(deviceId, {
        identity_signature: base64UrlEncode(signature),
        revoked_at: revokedAt,
        revocation_mode: mode,
      })

      await pinRevocation({
        userId: currentAuth.userId,
        deviceId,
        revokedAt,
        signature,
      })

      if (mode === 'security') {
        const workspacesToRotate = response?.workspaces_needing_kek_rotation || []
        const documentsForRotation: WorkspaceDocumentsForRotation[] = response?.documents_needing_dek_rotation || []

        if (workspacesToRotate.length > 0) {
          // Delegate to useKekRotation (handles TOFU pre-check, dialogs, rotation)
          await kekRotation.performKekRotation(deviceId, workspacesToRotate, documentsForRotation)
        } else {
          await onDevicesChangedRef.current()
        }
      } else {
        // retire mode: no rotation needed, just refresh device list
        await onDevicesChangedRef.current()
      }
    } catch (err) {
      onErrorRef.current(err instanceof Error ? err.message : 'Failed to revoke device')
    }
  }, [kekRotation.performKekRotation])

  return {
    revokeDevice,
    rotatingKek: kekRotation.rotatingKek,
    keyChangeDialogProps: kekRotation.keyChangeDialogProps,
  }
}
