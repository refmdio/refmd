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
  type KdfParams,
  type IdentityKeyPair,
} from '@/shared/lib/crypto'

// Re-export for convenience
export { ApiRequestError }

// Type aliases from generated schema
type MeResponse = components['schemas']['MeResponse']

/**
 * Registration result including recovery mnemonic
 */
export interface RegistrationResult {
  userId: string
  umk: Uint8Array
  identityKeys: IdentityKeyPair
  /** BIP39 24-word recovery mnemonic - user MUST save this */
  recoveryMnemonic: string
}

/**
 * Login result
 */
export interface LoginResult {
  userId: string
  email: string
  umk: Uint8Array
  identityKeys: IdentityKeyPair
  expiresAt: Date
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
  // We use a placeholder email to get params (server returns global params for any email)
  const saltResponse = await authApi.getSalt(email)
  const kdfParams: KdfParams = saltResponse.kdf_params

  // Step 2: Generate salt and derive keys from password
  const salt = new Uint8Array(32)
  crypto.getRandomValues(salt)
  const derivedKeys = await deriveAuthKeys(password, base64UrlEncode(salt), kdfParams)

  // Step 3: Generate and wrap UMK with PUK
  const umk = generateUmk()
  const { encryptedUmk, nonce: umkNonce } = wrapUmk(umk, derivedKeys.puk)

  // Step 4: Generate BIP39 recovery key and wrap UMK with RUK
  const recoveryKeyData = await generateRecoveryKey()
  const recoveryWrapped = wrapUmkWithRuk(umk, recoveryKeyData.ruk)

  // Step 5: Generate and encrypt identity keys
  const identityKeys = generateIdentityKeyPair()
  const encryptedIdentity = encryptIdentityKeys(identityKeys, umk)

  // Step 6: Build register request (using generated type)
  const request: components['schemas']['RegisterRequest'] = {
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
  }

  // Step 7: Send to server
  const response = await authApi.register(request)

  return {
    userId: response.id,
    umk,
    identityKeys,
    recoveryMnemonic: recoveryKeyData.mnemonic,
  }
}

/**
 * Login with email and password
 *
 * 1. Get salt from server
 * 2. Derive authKey and PUK
 * 3. Authenticate with server
 * 4. Decrypt UMK with PUK
 * 5. Decrypt identity keys with UMK (deriving public keys from private)
 */
export async function login(
  email: string,
  password: string,
  rememberMe: boolean = false
): Promise<LoginResult> {
  // Step 1: Get salt from server
  const saltResponse = await authApi.getSalt(email)

  // Step 2: Derive keys
  const derivedKeys = await deriveAuthKeys(password, saltResponse.salt, saltResponse.kdf_params)

  // Step 3: Login
  const loginResponse = await authApi.login({
    email,
    auth_key: derivedKeys.authKeyBase64,
    remember_me: rememberMe,
  })

  // Step 4: Decrypt UMK
  const encryptedUmk = base64UrlDecode(loginResponse.encrypted_umk)
  const umkNonce = base64UrlDecode(loginResponse.umk_nonce)
  const umk = unwrapUmk(encryptedUmk, umkNonce, derivedKeys.puk)

  // Step 5: Decrypt identity keys (public keys are derived from private keys)
  const identityKeys = decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: base64UrlDecode(loginResponse.encrypted_ecdh_private),
      ecdhPrivateNonce: base64UrlDecode(loginResponse.encrypted_ecdh_private_nonce),
      encryptedSigningPrivate: base64UrlDecode(loginResponse.encrypted_signing_private),
      signingPrivateNonce: base64UrlDecode(loginResponse.encrypted_signing_private_nonce),
    },
    umk
  )

  return {
    userId: loginResponse.user_id,
    email: loginResponse.email,
    umk,
    identityKeys,
    expiresAt: new Date(loginResponse.expires_at),
  }
}

/**
 * Get current session (for session restoration)
 *
 * Note: Full session restoration with UMK unwrap via DSK requires
 * additional implementation (Phase 2: Device Key management)
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
 * Logout
 */
export async function logout(): Promise<void> {
  await authApi.logout()
}
