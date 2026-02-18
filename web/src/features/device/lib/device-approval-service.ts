/**
 * Device Approval Service
 *
 * Pure functions for KEK/UMK distribution and trust state transfer
 * during device approval. Extracted from useDeviceApprovalFlow for testability.
 */

import { base64UrlDecode, base64UrlEncode, encryptUmkForDevice, encryptTrustState } from '@/shared/lib/crypto'
import { getAllTofuEntriesForUser } from '@/shared/lib/trust-store'
import { logger } from '@/shared/lib/logger'
import { workspaceApi, deviceApi, trustTransferApi, sseUrls, type DeviceSSEEvent } from '@/shared/api'
import { fetchAndDecryptKek, encryptAndSaveKekForDevice } from '@/entities/workspace'
import { waitForSSEEvent } from '@/shared/lib/sse'
import type { AuthState, DeviceState } from '@/shared/model/auth-types'

interface DistributeKeksParams {
  auth: AuthState
  currentDevice: DeviceState
  targetEcdhPk: Uint8Array
  approvedDeviceId: string
}

async function distributeKeks({ auth, currentDevice, targetEcdhPk, approvedDeviceId }: DistributeKeksParams): Promise<void> {
  const workspacesResponse = await workspaceApi.list()

  for (const item of workspacesResponse.workspaces) {
    const workspaceId = item.workspace.id
    try {
      const { kek, keyVersion } = await fetchAndDecryptKek(
        workspaceId,
        auth.userId,
        currentDevice.deviceId,
        currentDevice.deviceKeys,
      )

      await encryptAndSaveKekForDevice(
        kek,
        currentDevice.deviceKeys.ecdhPrivateKey,
        targetEcdhPk,
        approvedDeviceId,
        workspaceId,
        auth.userId,
        currentDevice.deviceId,
        keyVersion
      )
    } catch (err) {
      logger.warn('device-approval', `Skipping workspace ${workspaceId} KEK distribution (best-effort)`, err)
    }
  }
}

interface DistributeUmkParams {
  auth: AuthState & { umk: Uint8Array }
  currentDevice: DeviceState
  targetEcdhPk: Uint8Array
  approvedDeviceId: string
}

async function distributeUmk({ auth, currentDevice, targetEcdhPk, approvedDeviceId }: DistributeUmkParams): Promise<void> {
  const { encryptedUmk, nonce } = encryptUmkForDevice(
    auth.umk,
    currentDevice.deviceKeys.ecdhPrivateKey,
    targetEcdhPk,
    auth.userId,
    currentDevice.deviceId,
    approvedDeviceId
  )

  await deviceApi.distributeUmk(approvedDeviceId, {
    sender_device_id: currentDevice.deviceId,
    encrypted_umk: base64UrlEncode(encryptedUmk),
    nonce: base64UrlEncode(nonce),
  })
}

interface TransferTrustStateParams {
  auth: AuthState
  currentDevice: DeviceState
  targetEcdhPk: Uint8Array
  approvedDeviceId: string
}

async function transferTrustState({ auth, currentDevice, targetEcdhPk, approvedDeviceId }: TransferTrustStateParams): Promise<void> {
  const { nonce: nonceBase64, newDeviceId } = await waitForSSEEvent<{ nonce: string; newDeviceId: string }>({
    url: sseUrls.deviceEvents(),
    match: (data: unknown) => {
      const event = data as DeviceSSEEvent
      if (event.type === 'trust_transfer_nonce_ready' && event.new_device_id === approvedDeviceId) {
        return { nonce: event.nonce, newDeviceId: event.new_device_id }
      }
      return false
    },
    timeoutMs: 10000,
  })

  const tofuEntries = await getAllTofuEntriesForUser(auth.userId)
  if (tofuEntries.length === 0) return

  const transferNonce = base64UrlDecode(nonceBase64)
  const snapshot = { tofuEntries, transferNonce }

  const encrypted = encryptTrustState(
    snapshot,
    currentDevice.deviceKeys.ecdhPrivateKey,
    targetEcdhPk,
    currentDevice.deviceKeys.signingPrivateKey,
    {
      userId: auth.userId,
      senderDeviceId: currentDevice.deviceId,
      targetDeviceId: newDeviceId,
    }
  )

  await trustTransferApi.submitState({
    target_device_id: newDeviceId,
    transfer_nonce: nonceBase64,
    ciphertext: base64UrlEncode(encrypted.encryptedState),
    nonce: base64UrlEncode(encrypted.nonce),
    signature: base64UrlEncode(encrypted.signature),
  })
}

/**
 * Distribute KEKs, UMK, and trust state to the newly approved device.
 * KEK and trust state failures are non-fatal; UMK distribution is required.
 */
export async function approveAndDistributeKeys(params: DistributeKeksParams & { auth: AuthState & { umk: Uint8Array } }): Promise<void> {
  try {
    await distributeKeks(params)
  } catch (err) {
    logger.warn('device-approval', 'KEK distribution failed (non-fatal)', err)
  }

  await distributeUmk(params)

  try {
    await transferTrustState(params)
  } catch (err) {
    logger.warn('device-approval', 'Trust transfer failed (non-fatal)', err)
  }
}
