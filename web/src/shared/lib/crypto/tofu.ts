/**
 * TOFU (Trust On First Use) Verification Module
 *
 * Implements TOFU verification logic for device public keys.
 * Compares incoming keys against stored trusted keys to detect:
 * - First contact (new device)
 * - Known trusted device
 * - Identity key changes (potential MITM)
 * - ECDH-only key changes (abnormal, should be blocked)
 */

import {
  type TofuEntry,
  getTofuEntry,
  saveTofuEntry,
  updateLastSeen,
} from '../trust-store'
import { calculateFingerprint, formatFingerprint } from './fingerprint'

/**
 * TOFU verification status
 */
export type TofuStatus =
  | 'first_seen' // First contact - auto-trust
  | 'known_trusted' // Known device, keys match - normal processing
  | 'identity_key_changed' // Signing key changed - show warning dialog
  | 'ecdh_key_mismatch' // ECDH key changed but signing key same - block (abnormal)

/**
 * TOFU verification result
 */
export interface TofuVerifyResult {
  /** Verification status */
  status: TofuStatus
  /** Previously stored entry (if exists) */
  storedEntry?: TofuEntry
  /** New entry from incoming keys */
  newEntry: TofuEntry
  /** Old fingerprint (for identity_key_changed) */
  oldFingerprint?: string
  /** New fingerprint (for identity_key_changed) */
  newFingerprint?: string
}

/**
 * Compare two Uint8Arrays for equality
 */
function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  // Constant-time comparison
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return diff === 0
}

/**
 * Verify TOFU status for a device's public keys
 *
 * This function checks the incoming public keys against stored trusted keys
 * and returns the appropriate status for the caller to handle.
 *
 * @param userId User ID that owns the device
 * @param deviceId Device ID being verified
 * @param signingPublicKey Ed25519 signing public key (32 bytes)
 * @param ecdhPublicKey X25519 ECDH public key (32 bytes)
 * @returns TOFU verification result
 */
export async function verifyTofu(
  userId: string,
  deviceId: string,
  signingPublicKey: Uint8Array,
  ecdhPublicKey: Uint8Array
): Promise<TofuVerifyResult> {
  // Validate key lengths
  if (signingPublicKey.length !== 32) {
    throw new Error('Signing public key must be 32 bytes')
  }
  if (ecdhPublicKey.length !== 32) {
    throw new Error('ECDH public key must be 32 bytes')
  }

  const now = Date.now()
  const newEntry: TofuEntry = {
    userId,
    deviceId,
    signingPublicKey,
    ecdhPublicKey,
    firstSeenAt: now,
    lastSeenAt: now,
  }

  // Check for existing entry
  const storedEntry = await getTofuEntry(userId, deviceId)

  if (!storedEntry) {
    // First time seeing this device - auto-trust
    return {
      status: 'first_seen',
      newEntry,
    }
  }

  // Compare signing keys
  const signingKeyMatches = uint8ArrayEquals(
    storedEntry.signingPublicKey,
    signingPublicKey
  )

  // Compare ECDH keys
  const ecdhKeyMatches = uint8ArrayEquals(storedEntry.ecdhPublicKey, ecdhPublicKey)

  if (signingKeyMatches && ecdhKeyMatches) {
    // Both keys match - known trusted device
    return {
      status: 'known_trusted',
      storedEntry,
      newEntry: {
        ...newEntry,
        firstSeenAt: storedEntry.firstSeenAt, // Preserve original firstSeenAt
      },
    }
  }

  if (!signingKeyMatches) {
    // Signing key changed - this is significant, requires user confirmation
    const oldFingerprint = formatFingerprint(
      calculateFingerprint(storedEntry.signingPublicKey)
    )
    const newFingerprint = formatFingerprint(calculateFingerprint(signingPublicKey))

    return {
      status: 'identity_key_changed',
      storedEntry,
      newEntry,
      oldFingerprint,
      newFingerprint,
    }
  }

  // Signing key matches but ECDH key doesn't - this is abnormal
  // ECDH key should only change when identity key changes (device re-registration)
  return {
    status: 'ecdh_key_mismatch',
    storedEntry,
    newEntry,
  }
}

/**
 * Trust a device after verification
 *
 * Call this after verifyTofu() returns 'first_seen' to save the new entry,
 * or after the user confirms trust for 'identity_key_changed'.
 *
 * @param entry TOFU entry to save
 */
export async function trustDevice(entry: TofuEntry): Promise<void> {
  await saveTofuEntry(entry)
}

/**
 * Update last seen timestamp for a trusted device
 *
 * Call this after verifyTofu() returns 'known_trusted' to update
 * the last seen timestamp.
 *
 * @param userId User ID
 * @param deviceId Device ID
 */
export async function updateDeviceLastSeen(
  userId: string,
  deviceId: string
): Promise<void> {
  await updateLastSeen(userId, deviceId)
}

/**
 * Handle TOFU verification result
 *
 * Convenience function that handles common cases:
 * - first_seen: Auto-trusts and saves the entry
 * - known_trusted: Updates last seen timestamp
 * - Others: Returns the result for caller to handle
 *
 * @param result TOFU verification result
 * @returns The result (for identity_key_changed and ecdh_key_mismatch)
 */
export async function handleTofuResult(
  result: TofuVerifyResult
): Promise<TofuVerifyResult> {
  switch (result.status) {
    case 'first_seen':
      // Auto-trust new devices
      await trustDevice(result.newEntry)
      break

    case 'known_trusted':
      // Update last seen
      await updateDeviceLastSeen(result.newEntry.userId, result.newEntry.deviceId)
      break

    case 'identity_key_changed':
    case 'ecdh_key_mismatch':
      // Return for caller to handle (show warning, block, etc.)
      break
  }

  return result
}
