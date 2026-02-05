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
 * Minimum/maximum bounds for Argon2id parameters
 * Per design spec: memory 16-256MiB, iterations 2-10, parallelism 1-8
 * These protect against downgrade attacks or DoS via extreme parameters
 */
const KDF_BOUNDS = {
  memory_cost: { min: 16384, max: 262144 }, // 16 MiB - 256 MiB (in KiB)
  time_cost: { min: 2, max: 10 },
  parallelism: { min: 1, max: 8 },
} as const

/**
 * Check if a value is a safe positive integer
 */
function isSafePositiveInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    Number.isInteger(value) &&
    value > 0
  )
}

/**
 * Validate KDF parameters are within safe bounds
 * @throws Error if parameters are outside acceptable range or invalid type
 */
export function validateKdfParams(params: KdfParams): void {
  // Validate types first (protects against NaN, Infinity, non-integers)
  if (!isSafePositiveInteger(params.memory_cost)) {
    throw new Error(`Invalid memory_cost: must be a positive integer`)
  }
  if (!isSafePositiveInteger(params.time_cost)) {
    throw new Error(`Invalid time_cost: must be a positive integer`)
  }
  if (!isSafePositiveInteger(params.parallelism)) {
    throw new Error(`Invalid parallelism: must be a positive integer`)
  }

  // Validate ranges
  if (
    params.memory_cost < KDF_BOUNDS.memory_cost.min ||
    params.memory_cost > KDF_BOUNDS.memory_cost.max
  ) {
    throw new Error(
      `Invalid memory_cost: ${params.memory_cost}. Must be between ${KDF_BOUNDS.memory_cost.min} and ${KDF_BOUNDS.memory_cost.max}`
    )
  }
  if (
    params.time_cost < KDF_BOUNDS.time_cost.min ||
    params.time_cost > KDF_BOUNDS.time_cost.max
  ) {
    throw new Error(
      `Invalid time_cost: ${params.time_cost}. Must be between ${KDF_BOUNDS.time_cost.min} and ${KDF_BOUNDS.time_cost.max}`
    )
  }
  if (
    params.parallelism < KDF_BOUNDS.parallelism.min ||
    params.parallelism > KDF_BOUNDS.parallelism.max
  ) {
    throw new Error(
      `Invalid parallelism: ${params.parallelism}. Must be between ${KDF_BOUNDS.parallelism.min} and ${KDF_BOUNDS.parallelism.max}`
    )
  }
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
 * @param salt Salt from server (16 bytes as base64url per spec)
 * @param params KDF parameters from server
 */
/** Expected Argon2id salt size in bytes (per spec) */
const SALT_SIZE = 16

/** Expected Argon2 output hex string length (32 bytes = 64 hex chars) */
const ARGON2_HEX_LENGTH = 64

/** HKDF salt: 32 bytes of zeros (per spec) */
export const HKDF_ZERO_SALT = new Uint8Array(32)

/** HKDF info constants (per spec) */
const HKDF_INFO = {
  PASSWORD_AUTH: 'password_auth',
  PASSWORD_UNLOCK: 'password_unlock',
} as const

export async function deriveAuthKeys(
  password: string,
  saltBase64: string,
  params: KdfParams
): Promise<DerivedKeys> {
  // Validate KDF parameters before using them
  validateKdfParams(params)

  const salt = base64UrlDecode(saltBase64)

  // Validate salt length (16 bytes per spec)
  if (salt.length !== SALT_SIZE) {
    throw new Error(`Invalid salt length: ${salt.length}. Expected ${SALT_SIZE} bytes (16 bytes)`)
  }

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

  // Validate Argon2 output
  if (masterKeyHex.length !== ARGON2_HEX_LENGTH || !/^[0-9a-f]+$/i.test(masterKeyHex)) {
    throw new Error('Invalid Argon2 output')
  }

  // Convert hex to bytes
  const masterKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    masterKey[i] = parseInt(masterKeyHex.substr(i * 2, 2), 16)
  }

  // Step 2: HKDF → authKey (using 32-byte zero salt per spec)
  const authKeyInfo = new TextEncoder().encode(HKDF_INFO.PASSWORD_AUTH)
  const authKey = hkdf(sha256, masterKey, HKDF_ZERO_SALT, authKeyInfo, 32)

  // Step 3: HKDF → PUK (using 32-byte zero salt per spec)
  const pukInfo = new TextEncoder().encode(HKDF_INFO.PASSWORD_UNLOCK)
  const puk = hkdf(sha256, masterKey, HKDF_ZERO_SALT, pukInfo, 32)

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
  // Generate random salt (16 bytes per spec)
  const salt = new Uint8Array(SALT_SIZE)
  crypto.getRandomValues(salt)

  const derivedKeys = await deriveAuthKeys(password, base64UrlEncode(salt), params)

  return {
    salt,
    derivedKeys,
  }
}
