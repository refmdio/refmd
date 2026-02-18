/**
 * Self-Approve Device Service
 *
 * Creates a pending device and self-approves it with an identity signature.
 * Used during account recovery where the user has recovered their identity keys
 * and needs to register a new device without an existing approving device.
 */

import {
  generateDeviceKeyPair,
  base64UrlEncode,
  wrapAndStoreUmk,
  signDeviceApproval,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'
import { initializeDeviceState } from '@/shared/lib/device-init'
import { buildPendingDevicePayload } from '@/shared/lib/pending-device-payload'
import { deviceApi } from '@/shared/api'
import type { DeviceType } from '@/shared/lib/device'

export interface SelfApproveDeviceParams {
  userId: string
  identitySigningPrivateKey: Uint8Array
  umk: Uint8Array
  deviceName: string
  deviceType: DeviceType
}

export interface SelfApproveDeviceResult {
  deviceId: string
  deviceKeyPair: DeviceKeyPair
}

/**
 * Generate device keys, create a pending device, and self-approve it.
 *
 * Steps:
 * 1. Generate new device key pair
 * 2. Build + submit pending device payload
 * 3. Sign approval with identity key
 * 4. Submit approval
 * 5. Initialize device state (PoP + DSK + key storage)
 * 6. Wrap and store UMK
 */
export async function selfApproveDevice(
  params: SelfApproveDeviceParams
): Promise<SelfApproveDeviceResult> {
  const { userId, identitySigningPrivateKey, umk, deviceName, deviceType } = params

  // Step 1: Generate device keys + build pending payload
  const deviceKeyPair = generateDeviceKeyPair()
  const { payload } = buildPendingDevicePayload(deviceKeyPair, deviceName, deviceType)

  // Step 2: Sign approval
  const identitySignature = signDeviceApproval({
    device_signing_public_key: payload.signing_public_key,
    device_ecdh_public_key: payload.ecdh_public_key,
    client_nonce: payload.client_nonce,
  }, identitySigningPrivateKey)

  // Step 3: Create pending device + approve
  const pendingDevice = await deviceApi.createPendingDevice(payload)
  const approvalResponse = await deviceApi.approveDevice(pendingDevice.id, {
    identity_signature: base64UrlEncode(identitySignature),
  })

  // Step 4: Initialize device state (PoP + DSK + key storage)
  const dsk = await initializeDeviceState({
    deviceId: approvalResponse.id,
    deviceKeyPair,
    userId,
  })
  if (dsk) {
    await wrapAndStoreUmk(umk, dsk, userId)
  }

  return {
    deviceId: approvalResponse.id,
    deviceKeyPair,
  }
}
