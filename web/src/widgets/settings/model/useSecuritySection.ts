/**
 * Security Section Model Hook
 *
 * Orchestrates TOFU verification, device revocation, and pending device state.
 * Keeps SecuritySection UI pure by centralizing side effects and derived state.
 */

import { useEffect, useState, useCallback } from 'react'
import { type PendingDevice } from '@/shared/api'
import { usePendingDevices, useDeviceRevocation, useTofuVerification } from '@/features/device'
import { useAuthContext } from '@/shared/context'

export function useSecuritySection(onClose: () => void) {
  const { pendingDevices, showApprovalDialog } = usePendingDevices()
  const { auth, device: currentDevice } = useAuthContext()

  // TOFU verification hook (device list + key change dialogs)
  const tofu = useTofuVerification(auth?.userId)

  // Device revocation + KEK rotation hook
  const revocation = useDeviceRevocation(
    auth ? { userId: auth.userId, identityKeys: auth.identityKeys ?? null, umk: auth.umk ?? null } : null,
    currentDevice ? { deviceId: currentDevice.deviceId, deviceKeys: currentDevice.deviceKeys } : null,
    tofu.loadDevices,
    (msg) => tofu.setError(msg)
  )

  useEffect(() => {
    tofu.loadDevices()
  }, [tofu.loadDevices])

  const [revokeTargetId, setRevokeTargetId] = useState<string | null>(null)
  const revokeTargetDevice = revokeTargetId ? tofu.devices.find(d => d.id === revokeTargetId) : null

  const confirmRevoke = useCallback(async () => {
    if (!revokeTargetId) return
    setRevokeTargetId(null)
    await revocation.revokeDevice(revokeTargetId)
  }, [revokeTargetId, revocation])

  const reviewPending = useCallback((device: PendingDevice) => {
    onClose()
    showApprovalDialog(device)
  }, [onClose, showApprovalDialog])

  return {
    pendingDevices,
    tofu,
    revocation,
    revokeTargetId,
    revokeTargetDevice,
    setRevokeTargetId,
    confirmRevoke,
    reviewPending,
  }
}
