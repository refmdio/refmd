/**
 * KEK Rotation Service
 *
 * Pure functions for KEK/DEK rotation after device revocation.
 * Extracted from useKekRotation for testability.
 */

import { encryptionApi, deviceApi, ApiError } from '@/shared/api'
import type { components } from '@/shared/api'
import { base64UrlDecode, base64UrlEncode, generateDek, wrapDek, generateKek, processDeviceListTofu, type DeviceWithKeys } from '@/shared/lib/crypto'
import { logger } from '@/shared/lib/logger'
import { checkAndPinKeyVersion, getKeyVersionPin } from '@/shared/lib/anti-rollback'
import { clearKekCache, encryptAndSaveKekForDevice, wrapAndSaveKekBackup } from '@/entities/workspace'

import type { KeyChangeWarningItem } from '@/shared/model/key-change-types'

type Device = components['schemas']['DeviceResponse']
type WorkspaceDocumentsForRotation = components['schemas']['WorkspaceDocumentsForRotationResponse']

// --- TOFU verification for rotation ---

/** Result of TOFU verification phase during KEK rotation */
export interface TofuPhaseResult {
  aborted: boolean
  hasKeyChanges: boolean
  verifiedDevices: Device[]
}

/** Fetch active devices and run batch TOFU verification. */
export async function verifyDevicesForRotation(
  revokedDeviceId: string,
  userId: string,
  handlers: {
    onAborted: (device: DeviceWithKeys) => void
    onFailed: (failedDevices: DeviceWithKeys[], failedIds: Set<string>, activeDevices: Device[]) => Device[]
    onKeyChange: (items: KeyChangeWarningItem[], verifiedDevices: Device[]) => void
  },
): Promise<TofuPhaseResult> {
  const devicesResponse = await deviceApi.listDevices()
  const activeDevices = devicesResponse.devices.filter(d => d.id !== revokedDeviceId)

  let verifiedDevices = activeDevices
  const result = await processDeviceListTofu(activeDevices, userId, {
    onAborted: (device) => handlers.onAborted(device),
    onFailed: (failedDevices, failedIds) => {
      verifiedDevices = handlers.onFailed(failedDevices, failedIds, activeDevices)
    },
    onKeyChange: (items) => handlers.onKeyChange(items, verifiedDevices),
  })

  return {
    aborted: result.aborted,
    hasKeyChanges: !result.aborted && result.categorized.keyChangeItems.length > 0,
    verifiedDevices,
  }
}

// --- Pure helpers ---

/** Pending rotation context stored in a ref for stable callback access */
export interface RotationContext {
  activeDevices: Device[]
  workspacesToRotate: string[]
  documentsForRotation: WorkspaceDocumentsForRotation[]
  dialogDeviceIds: Set<string>
  trustedDeviceIds: Set<string>
}

/**
 * Build a fingerprint→deviceId lookup from key change items.
 */
export function buildFingerprintMap(items: KeyChangeWarningItem[]): Map<string, string> {
  const map = new Map<string, string>()
  for (const item of items) {
    map.set(item.newFingerprint, item.tofuNewEntry.deviceId)
  }
  return map
}

/**
 * Determine which devices were blocked by the user and filter them out.
 */
export function filterBlockedDevices(ctx: RotationContext): Device[] {
  const blockedDeviceIds = new Set(
    [...ctx.dialogDeviceIds].filter(id => !ctx.trustedDeviceIds.has(id))
  )
  return ctx.activeDevices.filter(d => !blockedDeviceIds.has(d.id))
}

export interface WorkspaceRotationFailure {
  workspaceId: string
  phase: 'kek_generation' | 'kek_distribution' | 'kek_backup' | 'dek_rotation'
  error: unknown
}

export interface KekRotationResult {
  completedWorkspaces: string[]
  failures: WorkspaceRotationFailure[]
}

async function rotateDeksForWorkspace(
  documentIds: string[],
  newKek: Uint8Array,
  workspaceId: string
): Promise<Array<{ documentId: string; error: unknown }>> {
  const failures: Array<{ documentId: string; error: unknown }> = []
  for (const documentId of documentIds) {
    try {
      const existingDekPin = await getKeyVersionPin('dek', documentId)
      const newDek = generateDek()
      const { encryptedDek, nonce: dekNonce } = wrapDek(newDek, newKek, documentId, workspaceId)
      const dekSaveResponse = await encryptionApi.saveDocumentKey(documentId, {
        encrypted_dek: base64UrlEncode(encryptedDek),
        nonce: base64UrlEncode(dekNonce),
        is_active: true,
      })
      if (existingDekPin && dekSaveResponse.key_version < existingDekPin.highestVersion) continue
      if (!(await checkAndPinKeyVersion('dek', documentId, dekSaveResponse.key_version))) continue
    } catch (err) {
      logger.warn('kek-rotation', `DEK rotation failed for document ${documentId} in workspace ${workspaceId}`, err)
      failures.push({ documentId, error: err })
    }
  }
  return failures
}

interface ExecuteKekRotationParams {
  userId: string
  umk: Uint8Array | null
  deviceId: string
  deviceKeys: { ecdhPrivateKey: Uint8Array }
  activeDevices: Device[]
  workspacesToRotate: string[]
  documentsForRotation: WorkspaceDocumentsForRotation[]
}

export async function executeKekRotation({
  userId,
  umk,
  deviceId,
  deviceKeys,
  activeDevices,
  workspacesToRotate,
  documentsForRotation,
}: ExecuteKekRotationParams): Promise<KekRotationResult> {
  const completedWorkspaces: string[] = []
  const failures: WorkspaceRotationFailure[] = []

  for (const workspaceId of workspacesToRotate) {
    try {
      const existingKey = await encryptionApi.getWorkspaceKey(workspaceId, deviceId)
      const currentVersion = existingKey.key_version

      if (!(await checkAndPinKeyVersion('kek', workspaceId, currentVersion))) continue

      const newVersion = currentVersion + 1
      const newKek = generateKek()

      const distributionFailedDevices: string[] = []
      for (const targetDevice of activeDevices) {
        try {
          await encryptAndSaveKekForDevice(
            newKek, deviceKeys.ecdhPrivateKey,
            base64UrlDecode(targetDevice.ecdh_public_key), targetDevice.id,
            workspaceId, userId, deviceId, newVersion
          )
        } catch (err) {
          logger.warn('kek-rotation', `KEK distribution failed for device ${targetDevice.id} in workspace ${workspaceId}`, err)
          distributionFailedDevices.push(targetDevice.id)
        }
      }
      if (distributionFailedDevices.length > 0) {
        failures.push({
          workspaceId,
          phase: 'kek_distribution',
          error: new Error(
            `KEK distribution failed for ${distributionFailedDevices.length} device(s): ${distributionFailedDevices.join(', ')}. ` +
            `Rotation will proceed for security (revoked device access must be revoked). ` +
            `Affected devices can recover via UMK backup.`
          ),
        })
      }

      if (umk) {
        try {
          await wrapAndSaveKekBackup(newKek, umk, workspaceId, userId, newVersion)
        } catch (err) {
          failures.push({ workspaceId, phase: 'kek_backup', error: err })
          // Continue — KEK is already distributed to devices
        }
      }

      await encryptionApi.completeKekRotation(workspaceId, newVersion)

      // Invalidate cached KEK so next access fetches the rotated key
      clearKekCache(workspaceId)

      if (!(await checkAndPinKeyVersion('kek', workspaceId, newVersion))) continue

      // DEK rotation
      const wsRotation = documentsForRotation.find(r => r.workspace_id === workspaceId)
      if (wsRotation) {
        const dekFailures = await rotateDeksForWorkspace(wsRotation.document_ids, newKek, workspaceId)
        if (dekFailures.length > 0) {
          failures.push({ workspaceId, phase: 'dek_rotation', error: new Error(`${dekFailures.length} document(s) failed DEK rotation`) })
        }
      }

      completedWorkspaces.push(workspaceId)
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Workspace was deleted or not found — skip
        continue
      }
      failures.push({ workspaceId, phase: 'kek_generation', error: err })
    }
  }

  return { completedWorkspaces, failures }
}
