/**
 * Key Derivation Functions
 *
 * Password → Master Key (Argon2id)
 * Master Key → authKey + PUK (HKDF-SHA256)
 */

import { argon2id } from 'hash-wasm'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64UrlEncode, base64UrlDecode } from './encoding'

/**
 * KDF parameters from server
 */
export interface KdfParams {
  memory_cost: number // in KB
  time_cost: number
  parallelism: number
}

/**
 * Derived keys from password
 */
export interface DerivedKeys {
  /** Master key (32 bytes) - never sent to server */
  masterKey: Uint8Array
  /** Auth key (32 bytes) - sent to server as base64url for bcrypt verification */
  authKey: Uint8Array
  /** Auth key as base64url string for API */
  authKeyBase64: string
  /** Password Unlock Key (32 bytes) - used to wrap/unwrap UMK */
  puk: Uint8Array
}

/**
 * Derive authKey and PUK from password using salt and KDF parameters
 *
 * Flow:
 * 1. Argon2id(password, salt) → masterKey (32 bytes)
 * 2. HKDF(masterKey, "refmd-auth-key") → authKey (32 bytes)
 * 3. HKDF(masterKey, "refmd-puk") → PUK (32 bytes)
 *
 * @param password User password
 * @param salt Salt from server (32 bytes as base64)
 * @param params KDF parameters from server
 */
export async function deriveAuthKeys(
  password: string,
  saltBase64: string,
  params: KdfParams
): Promise<DerivedKeys> {
  const salt = base64UrlDecode(saltBase64)

  // Step 1: Argon2id → Master Key
  const masterKeyHex = await argon2id({
    password,
    salt,
    parallelism: params.parallelism,
    iterations: params.time_cost,
    memorySize: params.memory_cost,
    hashLength: 32,
    outputType: 'hex',
  })

  // Convert hex to bytes
  const masterKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    masterKey[i] = parseInt(masterKeyHex.substr(i * 2, 2), 16)
  }

  // Step 2: HKDF → authKey
  const authKeyInfo = new TextEncoder().encode('refmd-auth-key')
  const authKey = hkdf(sha256, masterKey, undefined, authKeyInfo, 32)

  // Step 3: HKDF → PUK
  const pukInfo = new TextEncoder().encode('refmd-puk')
  const puk = hkdf(sha256, masterKey, undefined, pukInfo, 32)

  return {
    masterKey,
    authKey,
    authKeyBase64: base64UrlEncode(authKey),
    puk,
  }
}

/**
 * Derive keys for registration (also generates UMK and identity keys)
 * This is a convenience function that combines key derivation with key generation
 */
export async function deriveRegistrationKeys(
  password: string,
  params: KdfParams
): Promise<{
  salt: Uint8Array
  derivedKeys: DerivedKeys
}> {
  // Generate random salt (32 bytes)
  const salt = new Uint8Array(32)
  crypto.getRandomValues(salt)

  const derivedKeys = await deriveAuthKeys(password, base64UrlEncode(salt), params)

  return {
    salt,
    derivedKeys,
  }
}
