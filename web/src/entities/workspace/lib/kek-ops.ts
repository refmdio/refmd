/**
 * KEK Operations — Stateless, reusable operations
 *
 * Exported for use by other features (device-approval, KEK rotation).
 * Internal KEK lifecycle orchestration lives in kek-service.ts.
 */

import { encryptionApi } from '@/shared/api'
import {
  base64UrlDecode,
  base64UrlEncode,
  encryptKekForDevice,
  decryptKekFromDevice,
  wrapKekWithUmk,
  evaluateDeviceTofu,
  assertTofuTrustedOrThrow,
} from '@/shared/lib/crypto'
import { assertAndPinKeyVersion } from '@/shared/lib/anti-rollback'

export interface DecryptedWorkspaceKek {
  kek: Uint8Array
  keyVersion: number
}

/**
 * Encrypt KEK for a target device via ECDH and save to server.
 * Shared helper used by kek-service (restore/create), device-approval, and KEK rotation.
 */
export async function encryptAndSaveKekForDevice(
  kek: Uint8Array,
  ecdhPrivateKey: Uint8Array,
  targetEcdhPk: Uint8Array,
  targetDeviceId: string,
  workspaceId: string,
  userId: string,
  senderDeviceId: string,
  keyVersion: number
): Promise<void> {
  const { encryptedKek, nonce } = encryptKekForDevice(
    kek, ecdhPrivateKey, targetEcdhPk,
    workspaceId, userId, senderDeviceId, targetDeviceId
  )
  await encryptionApi.saveWorkspaceKey(workspaceId, {
    device_id: targetDeviceId,
    sender_device_id: senderDeviceId,
    key_version: keyVersion,
    encrypted_kek: base64UrlEncode(encryptedKek),
    nonce: base64UrlEncode(nonce),
    is_active: true,
  })
}

/**
 * Fetch and decrypt a workspace KEK for a device, with TOFU and anti-rollback.
 * Throws on TOFU failure, rollback detection, or missing sender keys.
 *
 * Shared between kek-service (fail-close) and device-approval-service (best-effort).
 */
export async function fetchAndDecryptKek(
  workspaceId: string,
  userId: string,
  deviceId: string,
  deviceKeys: { ecdhPrivateKey: Uint8Array; ecdhPublicKey: Uint8Array },
): Promise<DecryptedWorkspaceKek> {
  const response = await encryptionApi.getWorkspaceKey(workspaceId, deviceId)
  const encryptedKek = base64UrlDecode(response.encrypted_kek)
  const nonce = base64UrlDecode(response.nonce)
  const senderEcdhPublicKey = response.sender_ecdh_public_key
    ? base64UrlDecode(response.sender_ecdh_public_key)
    : deviceKeys.ecdhPublicKey
  const senderDeviceId = response.sender_device_id || deviceId

  // TOFU verification: verify sender device before using its public key (fail-close)
  if (senderDeviceId !== deviceId) {
    if (!response.sender_signing_public_key || !response.sender_ecdh_public_key) {
      throw new Error(
        'KEK sender signing/ECDH public key missing. Cannot verify sender identity. Decryption aborted.'
      )
    }
    const decision = await evaluateDeviceTofu(
      userId,
      senderDeviceId,
      response.sender_signing_public_key,
      response.sender_ecdh_public_key
    )

    assertTofuTrustedOrThrow(decision, 'KEK sender verification')
  }

  // Anti-rollback: check KEK version
  await assertAndPinKeyVersion('kek', workspaceId, response.key_version)

  const decryptedKek = decryptKekFromDevice(
    encryptedKek,
    nonce,
    deviceKeys.ecdhPrivateKey,
    senderEcdhPublicKey,
    workspaceId,
    userId,
    senderDeviceId,
    deviceId
  )

  return { kek: decryptedKek, keyVersion: response.key_version }
}

/**
 * Wrap KEK with UMK and save as backup to server.
 * Shared helper used by kek-service (backfill, create) and KEK rotation.
 */
export async function wrapAndSaveKekBackup(
  kek: Uint8Array,
  umk: Uint8Array,
  workspaceId: string,
  userId: string,
  keyVersion: number
): Promise<void> {
  const { encryptedKek, nonce } = wrapKekWithUmk(kek, umk, workspaceId, userId, keyVersion)
  await encryptionApi.saveWorkspaceKekBackup(workspaceId, {
    key_version: keyVersion,
    encrypted_kek: base64UrlEncode(encryptedKek),
    nonce: base64UrlEncode(nonce),
  })
}
