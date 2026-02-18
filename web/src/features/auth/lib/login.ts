/**
 * User Login
 *
 * Handles authentication, key derivation, and device key resolution.
 */

import { authApi } from '@/shared/api'
import {
  deriveAuthKeys,
  unwrapUmk,
  decryptIdentityKeysFromResponse,
  base64UrlDecode,
  wrapAndStoreUmk,
  clearSessionCache,
  loadDeviceId,
  wrapAndStorePdkUmk,
  storePdkForDeviceRegistration,
  storeSessionUmk,
  clearSessionUmk,
  type IdentityKeyPair,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'
import { ensureDsk, updatePdkWraps, resolveDeviceKeysWithPdkFallback } from './key-persistence'

export interface LoginResult {
  type: 'verified'
  userId: string
  email: string
  deviceId: string
  umk: Uint8Array
  identityKeys: IdentityKeyPair
  expiresAt: Date
  deviceKeys: DeviceKeyPair | null
}

export interface LoginDeviceRequired {
  type: 'device_required'
  userId: string
  email: string
  expiresAt: Date
}

export type LoginResponse = LoginResult | LoginDeviceRequired

/**
 * Login with email and password
 *
 * 1. Get salt from server
 * 2. Derive authKey and PUK
 * 3. Authenticate with server
 * 4. If device verified: Decrypt UMK and identity keys
 * 5. If device not verified: Return device_required result
 */
export async function login(
  email: string,
  password: string,
  rememberMe: boolean = false
): Promise<LoginResponse> {
  const saltResponse = await authApi.getSalt(email)
  const derivedKeys = await deriveAuthKeys(password, saltResponse.salt, saltResponse.kdf_params)

  const deviceId = await loadDeviceId()

  const loginResponse = await authApi.login({
    email,
    auth_key: derivedKeys.authKeyBase64,
    remember_me: rememberMe,
    device_id: deviceId ?? undefined,
  })

  if (!loginResponse.device_verified || !loginResponse.keys) {
    storePdkForDeviceRegistration(derivedKeys.pdk)
    return {
      type: 'device_required',
      userId: loginResponse.user_id,
      email: loginResponse.email,
      expiresAt: new Date(loginResponse.expires_at),
    }
  }

  if (!loginResponse.device_id) {
    throw new Error('Server returned verified device without device_id')
  }

  const verifiedDeviceId = loginResponse.device_id

  // Decrypt UMK
  const keys = loginResponse.keys
  const encryptedUmk = base64UrlDecode(keys.encrypted_umk)
  const umkNonce = base64UrlDecode(keys.umk_nonce)
  const umk = unwrapUmk(encryptedUmk, umkNonce, derivedKeys.puk, loginResponse.user_id)

  // Decrypt identity keys
  const identityKeys = decryptIdentityKeysFromResponse(keys, umk, loginResponse.user_id)

  // Handle UMK caching based on KMSI preference
  if (rememberMe) {
    const dsk = await ensureDsk()
    if (dsk) {
      await wrapAndStoreUmk(umk, dsk, loginResponse.user_id)
    }
    clearSessionUmk()
  } else {
    storeSessionUmk(umk, loginResponse.user_id)
    await clearSessionCache()
  }

  // Resolve device keys (DSK first, PDK fallback)
  const resolvedDeviceKeys = await resolveDeviceKeysWithPdkFallback({
    pdk: derivedKeys.pdk,
    userId: loginResponse.user_id,
    deviceId: verifiedDeviceId,
  })

  // Update PDK wraps with current password
  if (resolvedDeviceKeys) {
    updatePdkWraps(resolvedDeviceKeys, derivedKeys.pdk, umk, loginResponse.user_id, verifiedDeviceId)
  } else {
    wrapAndStorePdkUmk(umk, derivedKeys.pdk, loginResponse.user_id)
  }

  return {
    type: 'verified',
    userId: loginResponse.user_id,
    email: loginResponse.email,
    deviceId: verifiedDeviceId,
    umk,
    identityKeys,
    expiresAt: new Date(loginResponse.expires_at),
    deviceKeys: resolvedDeviceKeys,
  }
}
