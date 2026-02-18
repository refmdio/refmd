/**
 * User Registration
 *
 * Handles new user registration including key generation and device setup.
 */

import { authApi } from '@/shared/api'
import type { components } from '@/shared/api'
import {
  deriveAuthKeys,
  generateUmk,
  wrapUmk,
  generateIdentityKeyPair,
  encryptIdentityKeys,
  generateRecoveryKey,
  wrapUmkWithRuk,
  base64UrlEncode,
  storeDeviceId,
  generateDeviceKeyPair,
  generateClientNonce,
  sign,
  buildSignatureMessage,
  SIGNATURE_ACTION,
  wrapAndStorePdkDeviceKeys,
  type KdfParams,
  type IdentityKeyPair,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'
import { detectDeviceType, detectDeviceName } from '@/shared/lib/device'
import { persistDeviceKeysToDsk } from './key-persistence'

export interface RegistrationResult {
  userId: string
  deviceId: string
  umk: Uint8Array
  identityKeys: IdentityKeyPair
  deviceKeys: DeviceKeyPair
  /** BIP39 24-word recovery mnemonic - user MUST save this */
  recoveryMnemonic: string
}

/**
 * Register a new user
 *
 * 1. Get KDF params from server (using dummy email for global params)
 * 2. Generate salt and derive keys (authKey, PUK)
 * 3. Generate UMK and wrap with PUK
 * 4. Generate BIP39 recovery key and wrap UMK with RUK
 * 5. Generate identity keys and encrypt with UMK
 * 6. Send all to server
 *
 * @returns Registration result including recovery mnemonic that user MUST save
 */
export async function register(
  email: string,
  password: string,
  name: string
): Promise<RegistrationResult> {
  // Step 1: Get global KDF params from server
  const saltResponse = await authApi.getSalt(email)
  const kdfParams: KdfParams = saltResponse.kdf_params

  // Step 2: Generate salt and derive keys from password
  const salt = new Uint8Array(16)
  crypto.getRandomValues(salt)
  const derivedKeys = await deriveAuthKeys(password, base64UrlEncode(salt), kdfParams)

  // Generate user ID for AAD binding (client generates, server accepts)
  const userId = crypto.randomUUID()

  // Step 3: Generate and wrap UMK with PUK
  const umk = generateUmk()
  const { encryptedUmk, nonce: umkNonce } = wrapUmk(umk, derivedKeys.puk, userId)

  // Step 4: Generate BIP39 recovery key and wrap UMK with RUK
  const recoveryKeyData = await generateRecoveryKey()
  const recoveryWrapped = wrapUmkWithRuk(umk, recoveryKeyData.ruk, userId)

  // Step 5: Generate and encrypt identity keys
  const identityKeys = generateIdentityKeyPair()
  const encryptedIdentity = encryptIdentityKeys(identityKeys, umk, userId)

  // Step 6: Generate device keys and sign with identity key
  const deviceKeys = generateDeviceKeyPair()
  const clientNonce = generateClientNonce()

  const deviceSignMessage = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_REGISTRATION, {
    device_signing_public_key: base64UrlEncode(deviceKeys.signingPublicKey),
    device_ecdh_public_key: base64UrlEncode(deviceKeys.ecdhPublicKey),
    client_nonce: base64UrlEncode(clientNonce),
  })

  const deviceIdentitySignature = sign(deviceSignMessage, identityKeys.signingPrivate)

  const deviceType = detectDeviceType()
  const deviceName = detectDeviceName()

  // Step 7: Build register request
  const request: components['schemas']['RegisterRequest'] = {
    user_id: userId,
    email,
    name,
    auth_key: derivedKeys.authKeyBase64,
    salt: base64UrlEncode(salt),
    encrypted_umk: base64UrlEncode(encryptedUmk),
    umk_nonce: base64UrlEncode(umkNonce),
    recovery_encrypted_umk: base64UrlEncode(recoveryWrapped.encryptedUmk),
    recovery_nonce: base64UrlEncode(recoveryWrapped.nonce),
    ecdh_public_key: base64UrlEncode(identityKeys.ecdhPublic),
    signing_public_key: base64UrlEncode(identityKeys.signingPublic),
    encrypted_ecdh_private: base64UrlEncode(encryptedIdentity.encryptedEcdhPrivate),
    encrypted_ecdh_private_nonce: base64UrlEncode(encryptedIdentity.ecdhPrivateNonce),
    encrypted_signing_private: base64UrlEncode(encryptedIdentity.encryptedSigningPrivate),
    encrypted_signing_private_nonce: base64UrlEncode(encryptedIdentity.signingPrivateNonce),
    device_name: deviceName,
    device_type: deviceType,
    device_ecdh_public_key: base64UrlEncode(deviceKeys.ecdhPublicKey),
    device_signing_public_key: base64UrlEncode(deviceKeys.signingPublicKey),
    device_client_nonce: base64UrlEncode(clientNonce),
    device_identity_signature: base64UrlEncode(deviceIdentitySignature),
  }

  // Step 8: Send to server
  const response = await authApi.register(request)

  // Step 9: Store device keys (DSK preferred, PDK fallback)
  await storeDeviceId(response.device_id)
  await persistDeviceKeysToDsk(deviceKeys, response.id)

  // Step 10: PDK backup
  wrapAndStorePdkDeviceKeys(
    {
      ecdhPrivateKey: deviceKeys.ecdhPrivateKey,
      signingPrivateKey: deviceKeys.signingPrivateKey,
    },
    derivedKeys.pdk,
    response.id,
    response.device_id
  )

  return {
    userId: response.id,
    deviceId: response.device_id,
    umk,
    identityKeys,
    deviceKeys,
    recoveryMnemonic: recoveryKeyData.mnemonic,
  }
}
