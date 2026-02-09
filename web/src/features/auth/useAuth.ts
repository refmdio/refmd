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
  canPersistDsk,
  generateDsk,
  storeDsk,
  loadDsk,
  wrapAndStoreUmk,
  loadAndUnwrapUmk,
  clearSessionCache,
  clearDskData,
  hasCachedSession,
  wrapAndStoreDeviceKeys,
  loadAndUnwrapDeviceKeys,
  storeDeviceId,
  loadDeviceId,
  generateDeviceKeyPair,
  generateClientNonce,
  sign,
  buildSignatureMessage,
  SIGNATURE_ACTION,
  deriveEcdhPublicKey,
  deriveSigningPublicKey,
  // PDK fallback
  wrapAndStorePdkDeviceKeys,
  unwrapPdkDeviceKeys,
  hasPdkWrappedDeviceKeys,
  clearPdkWrappedDeviceKeys,
  wrapAndStorePdkUmk,
  clearPdkWrappedUmk,
  storePdkForDeviceRegistration,
  clearPdkEphemeral,
  // Session storage (for rememberMe=false)
  storeSessionUmk,
  loadSessionUmk,
  clearSessionUmk,
  type KdfParams,
  type IdentityKeyPair,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'
import { clearAllTofuEntries } from '@/shared/lib/trust-store'
import {
  clearAllRevocationPins,
  clearAllKeyVersionPins,
  clearAllMembershipLogs,
  clearAllDocumentStatePins,
} from '@/shared/lib/anti-rollback'
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
  /** Device keys (loaded from DSK or PDK) — null if neither is available */
  deviceKeys: DeviceKeyPair | null
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

  // Step 9: Store device keys (DSK preferred, PDK fallback)
  await storeDeviceId(response.device_id)
  const dskAvailable = await canPersistDsk()
  if (dskAvailable) {
    const dsk = await generateDsk()
    await storeDsk(dsk)
    await wrapAndStoreDeviceKeys(deviceKeys, dsk, response.id)
  }

  // Step 10: PDK backup - also wrap device keys with PDK for fallback
  // This allows session restoration even if DSK (IndexedDB non-exportable key) is lost
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
    // Store PDK in sessionStorage so device-register can wrap keys after approval
    storePdkForDeviceRegistration(derivedKeys.pdk)
    return {
      type: 'device_required',
      userId: loginResponse.user_id,
      email: loginResponse.email,
      expiresAt: new Date(loginResponse.expires_at),
      hasDevices: loginResponse.has_devices,
    }
  }

  // Verified device must have a device_id — server invariant
  if (!loginResponse.device_id) {
    throw new Error('Server returned verified device without device_id')
  }

  // After this point, device_id is guaranteed to be a string
  const verifiedDeviceId = loginResponse.device_id

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
    // Reuse existing DSK if available, otherwise generate new one if possible
    // This preserves device keys which are encrypted with DSK
    let dsk = await loadDsk()
    if (!dsk && (await canPersistDsk())) {
      dsk = await generateDsk()
      await storeDsk(dsk)
    }
    if (dsk) {
      await wrapAndStoreUmk(umk, dsk, loginResponse.user_id)
    }
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

  // Step 9: Load device keys and wrap with PDK for fallback
  let resolvedDeviceKeys: DeviceKeyPair | null = null

  // Try DSK first
  const dskForPdk = await loadDsk()
  if (dskForPdk) {
    const deviceKeysData = await loadAndUnwrapDeviceKeys(dskForPdk)
    if (deviceKeysData && deviceKeysData.userId === loginResponse.user_id) {
      resolvedDeviceKeys = {
        ecdhPrivateKey: deviceKeysData.ecdhPrivateKey,
        ecdhPublicKey: deviceKeysData.ecdhPublicKey,
        signingPrivateKey: deviceKeysData.signingPrivateKey,
        signingPublicKey: deviceKeysData.signingPublicKey,
      }
    }
  }

  // If DSK failed, try PDK fallback
  if (!resolvedDeviceKeys) {
    const pdkKeys = unwrapPdkDeviceKeys(derivedKeys.pdk)
    if (pdkKeys && pdkKeys.userId === loginResponse.user_id && pdkKeys.deviceId === verifiedDeviceId) {
      resolvedDeviceKeys = {
        ecdhPrivateKey: pdkKeys.ecdhPrivateKey,
        ecdhPublicKey: deriveEcdhPublicKey(pdkKeys.ecdhPrivateKey),
        signingPrivateKey: pdkKeys.signingPrivateKey,
        signingPublicKey: deriveSigningPublicKey(pdkKeys.signingPrivateKey),
      }
      // Re-store device keys in DSK if possible (so next reload doesn't need PDK)
      const dskForRestore = await loadDsk()
      if (dskForRestore) {
        await wrapAndStoreDeviceKeys(resolvedDeviceKeys, dskForRestore, loginResponse.user_id)
      } else if (await canPersistDsk()) {
        const newDsk = await generateDsk()
        await storeDsk(newDsk)
        await wrapAndStoreDeviceKeys(resolvedDeviceKeys, newDsk, loginResponse.user_id)
      }
    }
  }

  // Update PDK wraps with current password
  if (resolvedDeviceKeys) {
    wrapAndStorePdkDeviceKeys(
      {
        ecdhPrivateKey: resolvedDeviceKeys.ecdhPrivateKey,
        signingPrivateKey: resolvedDeviceKeys.signingPrivateKey,
      },
      derivedKeys.pdk,
      loginResponse.user_id,
      verifiedDeviceId
    )
  }
  // Always wrap UMK with PDK for fallback (works even without DSK)
  wrapAndStorePdkUmk(umk, derivedKeys.pdk, loginResponse.user_id)

  return {
    type: 'verified',
    userId: loginResponse.user_id,
    email: loginResponse.email,
    deviceId: verifiedDeviceId,
    umk,
    identityKeys,
    expiresAt: new Date(loginResponse.expires_at),
    hasDevices: loginResponse.has_devices,
    deviceKeys: resolvedDeviceKeys,
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
 * PDK session restoration result - includes device keys since DSK is unavailable
 */
export interface PdkSessionRestoreResult extends SessionRestoreResult {
  deviceId: string
  deviceKeys: {
    ecdhPrivateKey: Uint8Array
    ecdhPublicKey: Uint8Array
    signingPrivateKey: Uint8Array
    signingPublicKey: Uint8Array
  }
}

/**
 * Result when PDK fallback is needed (DSK failed but PDK-wrapped keys exist)
 */
export interface PdkFallbackRequired {
  type: 'pdk_fallback_required'
  email: string
}

/**
 * Restore session from cache
 *
 * Checks for UMK in order of preference:
 * 1. sessionStorage (for rememberMe=false, persists until tab close)
 * 2. IndexedDB wrapped with DSK (for rememberMe=true, persists across restarts)
 * 3. If DSK fails but PDK-wrapped keys exist, signals that password re-entry is needed
 *
 * Then:
 * 1. Call /api/auth/me to validate session and get encrypted keys
 * 2. Decrypt identity keys using UMK
 *
 * @returns Session data if restoration successful, PdkFallbackRequired if password needed, null otherwise
 */
export async function restoreSession(): Promise<SessionRestoreResult | PdkFallbackRequired | null> {
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

  // No cached UMK found - check if PDK fallback is available
  if (!umk || !cachedUserId) {
    if (hasPdkWrappedDeviceKeys()) {
      // PDK-wrapped keys exist but DSK failed. Need password re-entry.
      // Validate session first to get the email and auth_type for the prompt
      try {
        const meResponse = await authApi.me()
        // Only offer PDK fallback for password-auth users with verified devices
        // (OAuth users can't derive PDK, unverified devices will fail restoreSessionWithPdk)
        if (meResponse.auth_type === 'password' && meResponse.device_verified && meResponse.device_id) {
          return { type: 'pdk_fallback_required', email: meResponse.email }
        }
      } catch (error) {
        if (error instanceof ApiRequestError && error.status === 401) {
          return null
        }
        throw error
      }
    }
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

  // Device must be verified and keys must be present for session restoration
  if (!meResponse.device_verified || !meResponse.keys) {
    // Device not verified - cannot restore session with keys
    clearSessionUmk()
    return null
  }

  // Step 3: Verify device keys are accessible (needed for PoP)
  // Even if UMK was restored, if device keys can't be loaded from DSK,
  // we need PDK fallback to get device keys for PoP authentication.
  let deviceKeysAvailable = false
  const deviceId = await loadDeviceId()
  if (deviceId) {
    const dsk = await loadDsk()
    if (dsk) {
      const deviceKeysData = await loadAndUnwrapDeviceKeys(dsk)
      if (deviceKeysData && deviceKeysData.userId === meResponse.user_id) {
        deviceKeysAvailable = true
      }
    }
  }

  if (!deviceKeysAvailable) {
    if (hasPdkWrappedDeviceKeys() && meResponse.auth_type === 'password') {
      // UMK is available but device keys aren't loadable from DSK.
      // PDK-wrapped keys exist — need password re-entry to unlock them.
      return { type: 'pdk_fallback_required', email: meResponse.email }
    }
    // Neither DSK nor PDK device keys available — PoP cannot be established.
    // Force re-login so user can either recover device keys or re-register device.
    clearSessionUmk()
    return null
  }

  // Step 4: Decrypt identity keys
  const keys = meResponse.keys
  const identityKeys = decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: base64UrlDecode(keys.encrypted_ecdh_private),
      ecdhPrivateNonce: base64UrlDecode(keys.encrypted_ecdh_private_nonce),
      encryptedSigningPrivate: base64UrlDecode(keys.encrypted_signing_private),
      signingPrivateNonce: base64UrlDecode(keys.encrypted_signing_private_nonce),
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
 * Restore session using PDK fallback (password re-entry)
 *
 * Called when restoreSession() returns PdkFallbackRequired.
 * The user must provide their password to derive PDK and unwrap device keys.
 *
 * @param email User email for salt retrieval
 * @param password User password for PDK derivation
 * @returns Session data if restoration successful, null otherwise
 */
export async function restoreSessionWithPdk(
  email: string,
  password: string
): Promise<PdkSessionRestoreResult | null> {
  // Step 1: Derive PDK from password
  const saltResponse = await authApi.getSalt(email)
  const derivedKeys = await deriveAuthKeys(password, saltResponse.salt, saltResponse.kdf_params)

  // Step 2: Unwrap device keys with PDK
  const pdkKeys = unwrapPdkDeviceKeys(derivedKeys.pdk)
  if (!pdkKeys) {
    return null
  }

  // Step 3: Validate session with server
  let meResponse: MeResponse
  try {
    meResponse = await authApi.me()
  } catch (error) {
    if (error instanceof ApiRequestError && error.status === 401) {
      return null
    }
    throw error
  }

  // Verify user ID matches
  if (pdkKeys.userId !== meResponse.user_id) {
    return null
  }

  // Device must be verified, have a device_id, and keys must be present
  if (!meResponse.device_verified || !meResponse.device_id || !meResponse.keys) {
    return null
  }

  // Verify device ID matches PDK-stored device
  if (pdkKeys.deviceId !== meResponse.device_id) {
    return null
  }

  // Step 4: Decrypt UMK using PUK (with null guards for OAuth users)
  const keys = meResponse.keys
  if (!keys.encrypted_umk || !keys.umk_nonce) {
    // OAuth users don't have password-encrypted UMK
    return null
  }
  const encryptedUmk = base64UrlDecode(keys.encrypted_umk)
  const umkNonce = base64UrlDecode(keys.umk_nonce)
  const umk = unwrapUmk(encryptedUmk, umkNonce, derivedKeys.puk, meResponse.user_id)

  // Step 5: Decrypt identity keys
  const identityKeys = decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: base64UrlDecode(keys.encrypted_ecdh_private),
      ecdhPrivateNonce: base64UrlDecode(keys.encrypted_ecdh_private_nonce),
      encryptedSigningPrivate: base64UrlDecode(keys.encrypted_signing_private),
      signingPrivateNonce: base64UrlDecode(keys.encrypted_signing_private_nonce),
    },
    umk,
    meResponse.user_id
  )

  // Step 6: Derive public keys from private keys (PDK only stores private keys)
  const ecdhPublicKey = deriveEcdhPublicKey(pdkKeys.ecdhPrivateKey)
  const signingPublicKey = deriveSigningPublicKey(pdkKeys.signingPrivateKey)

  // Step 7: Persist device ID (may have been lost with IndexedDB)
  await storeDeviceId(meResponse.device_id)

  // Step 8: Re-establish DSK if possible, and update PDK wraps
  const dskAvailable = await canPersistDsk()
  if (dskAvailable) {
    const dsk = await generateDsk()
    await storeDsk(dsk)
    await wrapAndStoreDeviceKeys(
      {
        ecdhPrivateKey: pdkKeys.ecdhPrivateKey,
        ecdhPublicKey,
        signingPrivateKey: pdkKeys.signingPrivateKey,
        signingPublicKey,
      },
      dsk,
      meResponse.user_id
    )
    await wrapAndStoreUmk(umk, dsk, meResponse.user_id)
  }

  // Update PDK wraps with current password
  wrapAndStorePdkDeviceKeys(
    {
      ecdhPrivateKey: pdkKeys.ecdhPrivateKey,
      signingPrivateKey: pdkKeys.signingPrivateKey,
    },
    derivedKeys.pdk,
    meResponse.user_id,
    meResponse.device_id
  )
  wrapAndStorePdkUmk(umk, derivedKeys.pdk, meResponse.user_id)

  return {
    userId: meResponse.user_id,
    email: meResponse.email,
    umk,
    identityKeys,
    expiresAt: new Date(meResponse.expires_at),
    deviceId: meResponse.device_id,
    deviceKeys: {
      ecdhPrivateKey: pdkKeys.ecdhPrivateKey,
      ecdhPublicKey,
      signingPrivateKey: pdkKeys.signingPrivateKey,
      signingPublicKey,
    },
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
 * Normal logout: IndexedDB preserved, session destroyed.
 * User can re-login without password if DSK cache exists.
 *
 * Note: sessionStorage UMK is cleared since it's only for the current tab session
 */
export async function logout(): Promise<void> {
  clearSessionUmk()
  clearPdkEphemeral()
  await authApi.logout()
}

/**
 * Secure logout - clears all local data including IndexedDB
 *
 * Secure logout: IndexedDB cleared, session destroyed.
 * All local cryptographic material is erased.
 */
export async function secureLogout(): Promise<void> {
  clearSessionUmk()
  // Clear PDK-wrapped keys from localStorage (synchronous)
  clearPdkWrappedDeviceKeys()
  clearPdkWrappedUmk()
  clearPdkEphemeral()
  clearBrowserFingerprint()

  await Promise.all([
    authApi.logout(),
    clearDskData(),              // DSK, device keys, UMK cache in IndexedDB
    clearAllTofuEntries(),       // TOFU trust store
    clearAllRevocationPins(),    // Anti-rollback: revocation pins
    clearAllKeyVersionPins(),    // Anti-rollback: key version pins
    clearAllMembershipLogs(),    // Anti-rollback: membership logs
    clearAllDocumentStatePins(), // Anti-rollback: document state pins
  ])
}

/**
 * Clear browser fingerprint from localStorage
 *
 * Currently fingerprint storage is not implemented, but this ensures
 * the known key is cleared on secure logout when it is added.
 */
function clearBrowserFingerprint(): void {
  localStorage.removeItem('refmd-browser-fingerprint')
}
