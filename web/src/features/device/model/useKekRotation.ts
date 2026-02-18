/**
 * KEK Rotation Hook
 *
 * React state management layer for KEK/DEK rotation after device revocation.
 * Pure orchestration logic lives in lib/kek-rotation-service.ts.
 *
 * Responsibilities:
 * - React state (rotatingKek spinner)
 * - Ref-based context for async callback coordination
 * - Key change dialog queue via useKeyChangeFlow
 * - Delegates TOFU verification and rotation execution to service
 */

import { useState, useCallback, useRef } from 'react'
import { useLatest, useKeyChangeFlow } from '@/shared/hooks'
import { logger } from '@/shared/lib/logger'
import type { components } from '@/shared/api'
import {
  executeKekRotation,
  buildFingerprintMap,
  filterBlockedDevices,
  verifyDevicesForRotation,
  type RotationContext,
} from '../lib/kek-rotation-service'
import type { AuthInfo, CurrentDeviceInfo } from './types'

type Device = components['schemas']['DeviceResponse']
type WorkspaceDocumentsForRotation = components['schemas']['WorkspaceDocumentsForRotationResponse']

export interface UseKekRotationReturn {
  rotatingKek: boolean
  performKekRotation: (
    revokedDeviceId: string,
    workspacesToRotate: string[],
    documentsForRotation: WorkspaceDocumentsForRotation[]
  ) => Promise<void>
  keyChangeDialogProps: import('@/shared/hooks').KeyChangeWarningDialogProps | null
}

export function useKekRotation(
  auth: AuthInfo | null,
  currentDevice: CurrentDeviceInfo | null,
  onDevicesChanged: () => Promise<void>,
  onError: (message: string) => void
): UseKekRotationReturn {
  const authRef = useLatest(auth)
  const deviceRef = useLatest(currentDevice)
  const onDevicesChangedRef = useLatest(onDevicesChanged)
  const onErrorRef = useLatest(onError)

  const [rotatingKek, setRotatingKek] = useState(false)
  const rotationCtxRef = useRef<RotationContext | null>(null)
  const fingerprintToDeviceRef = useRef(new Map<string, string>())

  /** Execute the actual KEK/DEK rotation after all TOFU decisions are resolved. */
  const executeRotation = useCallback(async (
    activeDevices: Device[],
    workspacesToRotate: string[],
    documentsForRotation: WorkspaceDocumentsForRotation[]
  ) => {
    const currentAuth = authRef.current
    const currentDev = deviceRef.current
    if (!currentAuth || !currentDev) return

    const result = await executeKekRotation({
      userId: currentAuth.userId,
      umk: currentAuth.umk,
      deviceId: currentDev.deviceId,
      deviceKeys: currentDev.deviceKeys,
      activeDevices,
      workspacesToRotate,
      documentsForRotation,
    })

    if (result.failures.length > 0) {
      const uniqueIds = [...new Set(result.failures.map(f => f.workspaceId))]
      logger.error('kek-rotation', `${result.failures.length} failure(s) during rotation`, result.failures)
      onErrorRef.current(
        `KEK rotation partially failed for ${uniqueIds.length} workspace(s). ` +
        `${result.completedWorkspaces.length} workspace(s) completed successfully.`
      )
    }

    await onDevicesChangedRef.current()
  }, [])

  /** Complete the rotation after all key change dialogs are resolved. */
  const finishRotation = useCallback(async () => {
    const ctx = rotationCtxRef.current
    if (!ctx) return
    rotationCtxRef.current = null
    fingerprintToDeviceRef.current.clear()

    const filteredDevices = filterBlockedDevices(ctx)

    try {
      await executeRotation(filteredDevices, ctx.workspacesToRotate, ctx.documentsForRotation)
    } catch (err) {
      onErrorRef.current(err instanceof Error ? err.message : 'KEK rotation failed after key change resolution')
    } finally {
      setRotatingKek(false)
    }
  }, [executeRotation])

  const keyChange = useKeyChangeFlow({
    afterTrust: (item) => {
      const deviceId = fingerprintToDeviceRef.current.get(item.newFingerprint)
      if (deviceId) {
        rotationCtxRef.current?.trustedDeviceIds.add(deviceId)
      }
    },
    onQueueEmpty: () => finishRotation(),
    onCancel: () => finishRotation(),
  })

  /** Start KEK rotation with upfront TOFU verification. */
  const performKekRotation = useCallback(async (
    revokedDeviceId: string,
    workspacesToRotate: string[],
    documentsForRotation: WorkspaceDocumentsForRotation[]
  ) => {
    const currentAuth = authRef.current
    const currentDev = deviceRef.current
    if (!currentAuth || !currentDev) return

    setRotatingKek(true)

    try {
      const tofu = await verifyDevicesForRotation(revokedDeviceId, currentAuth.userId, {
        onAborted: async (device) => {
          onErrorRef.current(
            `KEK rotation aborted: Device "${device.name}" has a suspicious key mismatch. ` +
            `This may indicate a security issue.`
          )
          setRotatingKek(false)
          await onDevicesChangedRef.current()
        },
        onFailed: (failedDevices, failedIds, activeDevices) => {
          const names = failedDevices.map(d => d.name).join(', ')
          logger.warn('kek-rotation', `Excluding ${failedIds.size} device(s) with TOFU failures: ${names}`)
          return activeDevices.filter(d => !failedIds.has(d.id))
        },
        onKeyChange: (items, verifiedDevices) => {
          fingerprintToDeviceRef.current = buildFingerprintMap(items)
          rotationCtxRef.current = {
            activeDevices: verifiedDevices,
            workspacesToRotate,
            documentsForRotation,
            dialogDeviceIds: new Set(items.map(i => i.tofuNewEntry.deviceId)),
            trustedDeviceIds: new Set(),
          }
          keyChange.set(items)
        },
      })

      if (tofu.aborted || tofu.hasKeyChanges) return

      await executeRotation(tofu.verifiedDevices, workspacesToRotate, documentsForRotation)
    } catch (err) {
      onErrorRef.current(err instanceof Error ? err.message : 'KEK rotation failed')
    }

    setRotatingKek(false)
  }, [executeRotation, keyChange.set])

  return {
    rotatingKek,
    performKekRotation,
    keyChangeDialogProps: keyChange.dialogProps,
  }
}
