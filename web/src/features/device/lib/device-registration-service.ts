/**
 * Device Registration Service
 *
 * Handles UMK decryption, key storage, PDK fallback, and identity key retrieval
 * during device registration approval. Extracted from useDeviceRegistrationApproval
 * for testability and reduced hook complexity.
 */

import {
  decryptUmkFromDevice,
  decryptIdentityKeysFromResponse,
  base64UrlDecode,
  base64UrlEncode,
  wrapAndStoreUmk,
  storeSessionUmk,
  updatePdkWraps,
  loadAndClearPdkForDeviceRegistration,
  type DeviceKeyPair,
  type IdentityKeyPair,
} from '@/shared/lib/crypto'
import { authApi, deviceApi } from '@/shared/api'

export interface CompleteDeviceRegistrationParams {
  umkData: {
    encrypted_umk: string
    nonce: string
    sender_ecdh_public_key: string
    sender_device_id: string
  }
  senderEcdhPublicKey: Uint8Array
  deviceKeyPair: DeviceKeyPair
  userId: string
  deviceId: string
  dsk: CryptoKey | null
}

export interface CompleteDeviceRegistrationResult {
  umk: Uint8Array
  identityKeys: IdentityKeyPair
}

/**
 * Complete device registration after TOFU verification passes.
 *
 * Steps:
 * 1. Decrypt UMK using ECDH shared secret
 * 2. Store UMK (DSK-wrapped + session)
 * 3. PDK fallback wrapping (if PDK available)
 * 4. Fetch and decrypt identity keys from server
 */
export async function completeDeviceRegistration(
  params: CompleteDeviceRegistrationParams
): Promise<CompleteDeviceRegistrationResult> {
  const { umkData, senderEcdhPublicKey, deviceKeyPair, userId, deviceId, dsk } = params

  // Step 1: Decrypt UMK using ECDH
  const encryptedUmk = base64UrlDecode(umkData.encrypted_umk)
  const nonce = base64UrlDecode(umkData.nonce)

  const umk = decryptUmkFromDevice(
    encryptedUmk,
    nonce,
    deviceKeyPair.ecdhPrivateKey,
    senderEcdhPublicKey,
    userId,
    umkData.sender_device_id,
    deviceId
  )

  // Step 2: Store UMK locally
  if (dsk) {
    await wrapAndStoreUmk(umk, dsk, userId)
  }
  storeSessionUmk(umk, userId)

  // Step 3: PDK fallback wrapping
  const pdk = loadAndClearPdkForDeviceRegistration()
  if (pdk) {
    updatePdkWraps(deviceKeyPair, pdk, umk, userId, deviceId)
  }

  // Step 4: Fetch and decrypt identity keys
  const meResponse = await authApi.me()
  if (!meResponse.keys) {
    throw new Error('Device not verified: no keys returned from server')
  }
  const identityKeys = decryptIdentityKeysFromResponse(meResponse.keys, umk, userId)

  return { umk, identityKeys }
}

/**
 * Check if a device with the given signing public key has been approved (is active).
 * Returns the device ID if found, or null.
 */
export async function findApprovedDeviceBySigningKey(
  signingPublicKey: Uint8Array
): Promise<string | null> {
  const ourSigningPk = base64UrlEncode(signingPublicKey)
  const { devices } = await deviceApi.listDevices()
  const match = devices.find((d) => d.signing_public_key === ourSigningPk)
  return match?.id ?? null
}
