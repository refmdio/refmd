/**
 * Auth feature - combines crypto module with API client
 */

import { authApi, ApiRequestError } from '@/shared/api'
import type { components } from '@/shared/api'
import {
  deriveAuthKeys,
  generateUmk,
  wrapUmk,
  unwrapUmk,
  generateIdentityKeyPair,
  encryptIdentityKeys,
  decryptIdentityPrivateKeys,
  generateRecoveryKey,
  wrapUmkWithRuk,
  base64UrlEncode,
  base64UrlDecode,
  generateDsk,
  storeDsk,
  loadDsk,
  wrapAndStoreUmk,
  loadAndUnwrapUmk,
  clearSessionCache,
  clearDskData,
  hasCachedSession,
  wrapAndStoreDeviceKeys,
  storeDeviceId,
  loadDeviceId,
  generateDeviceKeyPair,
  generateClientNonce,
  sign,
  buildSignatureMessage,
  SIGNATURE_ACTION,
  // Session storage (for rememberMe=false)
  storeSessionUmk,
  loadSessionUmk,
  clearSessionUmk,
  type KdfParams,
  type IdentityKeyPair,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'
import { detectDeviceType, detectDeviceName } from '@/shared/lib/device'

// Re-export for convenience
export { ApiRequestError }

// Type aliases from generated schema
type MeResponse = components['schemas']['MeResponse']

/**
 * Registration result including recovery mnemonic
 */
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
 * Login result for verified devices (has access to keys)
 */
export interface LoginResult {
  type: 'verified'
  userId: string
  email: string
  deviceId: string
  umk: Uint8Array
  identityKeys: IdentityKeyPair
  expiresAt: Date
  hasDevices: boolean
}

/**
 * Login result for new/unverified devices (needs device registration)
 */
export interface LoginDeviceRequired {
  type: 'device_required'
  userId: string
  email: string
  expiresAt: Date
  hasDevices: boolean
}

/**
 * Combined login result type
 */
export type LoginResponse = LoginResult | LoginDeviceRequired

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
  // We use a placeholder email to get params (server returns global params for any email)
  const saltResponse = await authApi.getSalt(email)
  const kdfParams: KdfParams = saltResponse.kdf_params

  // Step 2: Generate salt and derive keys from password
  // Note: salt is 16 bytes per spec
  const salt = new Uint8Array(16)
  crypto.getRandomValues(salt)
  const derivedKeys = await deriveAuthKeys(password, base64UrlEncode(salt), kdfParams)

  // Generate user ID for AAD binding (client generates, server accepts)
  // This ensures AAD is bound to user context before server response
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

  // Build JCS signature message for device registration
  const deviceSignMessage = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_REGISTRATION, {
    device_signing_public_key: base64UrlEncode(deviceKeys.signingPublicKey),
    device_ecdh_public_key: base64UrlEncode(deviceKeys.ecdhPublicKey),
    client_nonce: base64UrlEncode(clientNonce),
  })

  // Sign with identity signing private key
  const deviceIdentitySignature = sign(deviceSignMessage, identityKeys.signingPrivate)

  // Detect device type
  const deviceType = detectDeviceType()
  const deviceName = detectDeviceName()

  // Step 7: Build register request (using generated type)
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

  // Step 9: Store device keys in IndexedDB (encrypted by DSK)
  const dsk = await generateDsk()
  await storeDsk(dsk)
  await wrapAndStoreDeviceKeys(deviceKeys, dsk, response.id)
  await storeDeviceId(response.device_id)

  return {
    userId: response.id,
    deviceId: response.device_id,
    umk,
    identityKeys,
    deviceKeys,
    recoveryMnemonic: recoveryKeyData.mnemonic,
  }
}

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
  // Step 1: Get salt from server
  const saltResponse = await authApi.getSalt(email)

  // Step 2: Derive keys
  const derivedKeys = await deriveAuthKeys(password, saltResponse.salt, saltResponse.kdf_params)

  // Step 3: Load existing device_id if available (for session binding)
  const deviceId = await loadDeviceId()

  // Step 4: Login
  const loginResponse = await authApi.login({
    email,
    auth_key: derivedKeys.authKeyBase64,
    remember_me: rememberMe,
    device_id: deviceId ?? undefined,
  })

  // Step 5: Check if device is verified
  if (!loginResponse.device_verified || !loginResponse.keys) {
    // Device not verified - needs to go through PendingDevice flow
    return {
      type: 'device_required',
      userId: loginResponse.user_id,
      email: loginResponse.email,
      expiresAt: new Date(loginResponse.expires_at),
      hasDevices: loginResponse.has_devices,
    }
  }

  // Step 6: Decrypt UMK (using user_id for AAD)
  const keys = loginResponse.keys
  const encryptedUmk = base64UrlDecode(keys.encrypted_umk)
  const umkNonce = base64UrlDecode(keys.umk_nonce)
  const umk = unwrapUmk(encryptedUmk, umkNonce, derivedKeys.puk, loginResponse.user_id)

  // Step 7: Decrypt identity keys (public keys are derived from private keys)
  const identityKeys = decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: base64UrlDecode(keys.encrypted_ecdh_private),
      ecdhPrivateNonce: base64UrlDecode(keys.encrypted_ecdh_private_nonce),
      encryptedSigningPrivate: base64UrlDecode(keys.encrypted_signing_private),
      signingPrivateNonce: base64UrlDecode(keys.encrypted_signing_private_nonce),
    },
    umk,
    loginResponse.user_id
  )

  // Step 8: Handle UMK caching based on KMSI preference
  if (rememberMe) {
    // rememberMe=true: Store UMK in IndexedDB (persists across browser restarts)
    // Reuse existing DSK if available, otherwise generate new one
    // This preserves device keys which are encrypted with DSK
    let dsk = await loadDsk()
    if (!dsk) {
      dsk = await generateDsk()
      await storeDsk(dsk)
    }
    await wrapAndStoreUmk(umk, dsk, loginResponse.user_id)
    // Clear sessionStorage UMK if it exists (we're using IndexedDB now)
    clearSessionUmk()
  } else {
    // rememberMe=false: Store UMK in sessionStorage (persists until tab close)
    // This allows page reloads without requiring re-authentication
    storeSessionUmk(umk, loginResponse.user_id)
    // Clear IndexedDB UMK cache (don't persist across browser restarts)
    // DSK and device keys are preserved for device identity
    await clearSessionCache()
  }

  return {
    type: 'verified',
    userId: loginResponse.user_id,
    email: loginResponse.email,
    deviceId: loginResponse.device_id!,
    umk,
    identityKeys,
    expiresAt: new Date(loginResponse.expires_at),
    hasDevices: loginResponse.has_devices,
  }
}

/**
 * Session restoration result
 */
export interface SessionRestoreResult {
  userId: string
  email: string
  umk: Uint8Array
  identityKeys: IdentityKeyPair
  expiresAt: Date
}

/**
 * Restore session from cache
 *
 * Checks for UMK in order of preference:
 * 1. sessionStorage (for rememberMe=false, persists until tab close)
 * 2. IndexedDB wrapped with DSK (for rememberMe=true, persists across restarts)
 *
 * Then:
 * 1. Call /api/auth/me to validate session and get encrypted keys
 * 2. Decrypt identity keys using UMK
 *
 * @returns Session data if restoration successful, null otherwise
 */
export async function restoreSession(): Promise<SessionRestoreResult | null> {
  // Step 1: Try to get UMK from cache (sessionStorage first, then IndexedDB)
  let umk: Uint8Array | null = null
  let cachedUserId: string | null = null

  // First, check sessionStorage (rememberMe=false sessions)
  const sessionData = loadSessionUmk()
  if (sessionData) {
    umk = sessionData.umk
    cachedUserId = sessionData.userId
  }

  // If not in sessionStorage, check IndexedDB (rememberMe=true sessions)
  if (!umk && (await hasCachedSession())) {
    const dsk = await loadDsk()
    if (dsk) {
      const unwrapped = await loadAndUnwrapUmk(dsk)
      if (unwrapped) {
        umk = unwrapped.umk
        cachedUserId = unwrapped.userId
      }
    }
  }

  // No cached UMK found
  if (!umk || !cachedUserId) {
    return null
  }

  // Step 2: Validate session with server
  let meResponse: MeResponse
  try {
    meResponse = await authApi.me()
  } catch (error) {
    if (error instanceof ApiRequestError && error.status === 401) {
      // Session expired/invalid. Keep DSK-backed data so device registration
      // persists across tab close and user can re-authenticate without losing keys.
      clearSessionUmk()
      return null
    }
    throw error
  }

  // Verify user ID matches
  if (cachedUserId !== meResponse.user_id) {
    // Different user, clear cached data
    clearSessionUmk()
    await clearDskData()
    return null
  }

  // Step 3: Decrypt identity keys
  const identityKeys = decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: base64UrlDecode(meResponse.encrypted_ecdh_private),
      ecdhPrivateNonce: base64UrlDecode(meResponse.encrypted_ecdh_private_nonce),
      encryptedSigningPrivate: base64UrlDecode(meResponse.encrypted_signing_private),
      signingPrivateNonce: base64UrlDecode(meResponse.encrypted_signing_private_nonce),
    },
    umk,
    meResponse.user_id
  )

  return {
    userId: meResponse.user_id,
    email: meResponse.email,
    umk,
    identityKeys,
    expiresAt: new Date(meResponse.expires_at),
  }
}

/**
 * Get current session (for session validation only, without UMK)
 */
export async function getCurrentUser(): Promise<MeResponse | null> {
  try {
    return await authApi.me()
  } catch (error) {
    if (error instanceof ApiRequestError && error.status === 401) {
      return null
    }
    throw error
  }
}

/**
 * Logout (normal) - keeps IndexedDB cache for quick re-login
 *
 * Per deletion-semantics.md:
 * - Normal logout: IndexedDB preserved, session destroyed
 * - User can re-login without password if DSK cache exists
 *
 * Note: sessionStorage UMK is cleared since it's only for the current tab session
 */
export async function logout(): Promise<void> {
  clearSessionUmk()
  await authApi.logout()
}

/**
 * Secure logout - clears all local data including IndexedDB
 *
 * Per deletion-semantics.md:
 * - Secure logout: IndexedDB cleared, session destroyed
 * - All local cryptographic material is erased
 */
export async function secureLogout(): Promise<void> {
  clearSessionUmk()
  await Promise.all([
    authApi.logout(),
    clearDskData(),
  ])
}
