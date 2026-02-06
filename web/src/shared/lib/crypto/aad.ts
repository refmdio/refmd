/**
 * AAD (Additional Authenticated Data) constants and helpers
 *
 * Per spec: All AEAD operations must include AAD with protocol/version/purpose
 * AAD is always reconstructed, never stored with ciphertext
 */

/**
 * Signature protocol constants
 */
export const SIGNATURE_PROTOCOL = {
  protocol: 'doclock-v1',
  version: 1,
} as const

/**
 * Signature action constants (per spec)
 * Used in signature protocol for context binding
 */
export const SIGNATURE_ACTION = {
  /** Trust state transfer signature */
  TRUST_STATE_TRANSFER: 'transfer_trust_state',
  /** Proof of Possession challenge signature */
  POP_CHALLENGE: 'pop_challenge',
  /** Device approval signature */
  DEVICE_APPROVAL: 'device_approval',
  /** Device registration (identity key signs device keys at registration) */
  DEVICE_REGISTRATION: 'device_registration',
  /** Device revocation (identity key signs revocation event) */
  DEVICE_REVOCATION: 'device_revocation',
  /** Document update (device signing key signs update metadata) */
  DOCUMENT_UPDATE: 'document_update',
} as const

export type SignatureAction = (typeof SIGNATURE_ACTION)[keyof typeof SIGNATURE_ACTION]

/**
 * AAD purpose constants (per spec)
 */
export const AAD_PURPOSE = {
  // UMK related
  UMK_WRAP: 'umk_wrap',
  DSK_UMK_CACHE: 'dsk_umk_cache',
  PDK_UMK_WRAP: 'pdk_umk_wrap',
  RECOVERY_UMK_WRAP: 'recovery_umk_wrap',
  DEVICE_UMK_WRAP: 'device_umk_wrap',

  // Identity key related
  IDENTITY_ECDH: 'identity_ecdh',
  IDENTITY_SIGNING: 'identity_signing',

  // Device key related
  DSK_DEVICE_ECDH_PRIVATE: 'dsk_device_ecdh_private',
  DSK_DEVICE_SIGNING_PRIVATE: 'dsk_device_signing_private',
  PDK_DEVICE_ECDH_PRIVATE: 'pdk_device_ecdh_private',
  PDK_DEVICE_SIGNING_PRIVATE: 'pdk_device_signing_private',

  // KEK/DEK related
  KEK_WRAP: 'kek_wrap',
  DEVICE_KEK_WRAP: 'device_kek_wrap',
  DEK_WRAP: 'dek_wrap',
  DOCUMENT_CONTENT: 'document_content',
  DOCUMENT_TAG_VALUE: 'document_tag_value',

  // UMK KEK backup
  UMK_KEK_BACKUP: 'umk_kek_backup',

  // Share related
  SHARE_DEK_WRAP: 'share_dek_wrap',
  SHARE_DEK_WRAP_PASSWORD: 'share_dek_wrap_password',

  // Trust state transfer
  TRUST_STATE_TRANSFER: 'trust_state_transfer',

  // Server internal
  SERVER_AUTH_KEY_WRAP: 'server_auth_key_wrap',
} as const

export type AadPurpose = (typeof AAD_PURPOSE)[keyof typeof AAD_PURPOSE]

/**
 * AAD common header interface
 */
export interface AadCommonHeader {
  protocol: 'doclock-v1'
  version: 1
  purpose: AadPurpose
}

/**
 * Build AAD bytes from header object
 * Uses RFC 8785 JSON Canonicalization Scheme (recursively sorted keys, no whitespace)
 *
 * @param header AAD header object
 * @returns Canonical JSON encoded as UTF-8 bytes
 * @throws Error if header contains undefined or non-finite numbers
 */
export function buildAad(header: AadCommonHeader & Record<string, unknown>): Uint8Array {
  // Use canonicalizeBytes for full RFC 8785 JCS compliance (recursive sorting + validation)
  return canonicalizeBytes(header)
}

/**
 * Build AAD for UMK wrap (with PUK)
 */
export function buildUmkWrapAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.UMK_WRAP,
    user_id: userId,
  })
}

/**
 * Build AAD for recovery UMK wrap
 */
export function buildRecoveryUmkWrapAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.RECOVERY_UMK_WRAP,
    user_id: userId,
  })
}

/**
 * Build AAD for identity ECDH private key encryption
 */
export function buildIdentityEcdhAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.IDENTITY_ECDH,
    user_id: userId,
  })
}

/**
 * Build AAD for identity signing private key encryption
 */
export function buildIdentitySigningAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.IDENTITY_SIGNING,
    user_id: userId,
  })
}

/**
 * Build AAD for device UMK distribution (UMK encrypted with ECDH shared secret)
 */
export function buildDeviceUmkDistributionAad(
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string
): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DEVICE_UMK_WRAP,
    user_id: userId,
    sender_device_id: senderDeviceId,
    target_device_id: targetDeviceId,
  })
}

/**
 * Build AAD for device KEK distribution (KEK encrypted with ECDH shared secret)
 */
export function buildDeviceKekDistributionAad(
  workspaceId: string,
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string
): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DEVICE_KEK_WRAP,
    workspace_id: workspaceId,
    user_id: userId,
    sender_device_id: senderDeviceId,
    target_device_id: targetDeviceId,
  })
}

/**
 * Build AAD for UMK KEK backup (KEK encrypted with UMK)
 * Includes key_version to prevent version downgrade/mixup attacks.
 */
export function buildUmkKekBackupAad(
  workspaceId: string,
  userId: string,
  keyVersion: number
): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.UMK_KEK_BACKUP,
    workspace_id: workspaceId,
    user_id: userId,
    key_version: keyVersion,
  })
}

/**
 * Build AAD for DEK wrap (DEK encrypted with KEK)
 */
export function buildDekWrapAad(documentId: string, workspaceId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DEK_WRAP,
    document_id: documentId,
    workspace_id: workspaceId,
  })
}

/**
 * Build AAD for document content encryption (Yjs updates encrypted with DEK)
 */
export function buildDocumentContentAad(documentId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DOCUMENT_CONTENT,
    document_id: documentId,
  })
}

/**
 * Validate number for JCS compliance per signature-protocol.md:
 * - Must be finite (no NaN, Infinity)
 * - Must be safe integer (no floating point, within 53-bit signed range)
 * - No exponential notation (handled by JSON.stringify for safe integers)
 *
 * @param num Number to validate
 * @throws Error if number is not JCS compliant
 */
function validateJcsNumber(num: number): void {
  if (!Number.isFinite(num)) {
    throw new Error('JCS error: non-finite numbers (NaN, Infinity) not allowed')
  }
  if (!Number.isInteger(num)) {
    throw new Error('JCS error: floating point numbers not allowed (integers only)')
  }
  if (!Number.isSafeInteger(num)) {
    throw new Error('JCS error: number outside safe integer range (53-bit signed)')
  }
}

/**
 * Compare strings by Unicode code point order (RFC 8785 requirement).
 * JavaScript's default sort uses UTF-16 code units, which differs for
 * characters outside the BMP. This function ensures correct ordering.
 *
 * @param a First string
 * @param b Second string
 * @returns Comparison result (-1, 0, or 1)
 */
function compareByCodePoint(a: string, b: string): number {
  // For ASCII-only strings (common case), this is equivalent to default sort
  // For strings with characters outside BMP, we need code point comparison
  const aCodePoints = [...a].map(c => c.codePointAt(0)!)
  const bCodePoints = [...b].map(c => c.codePointAt(0)!)
  const minLen = Math.min(aCodePoints.length, bCodePoints.length)

  for (let i = 0; i < minLen; i++) {
    if (aCodePoints[i] !== bCodePoints[i]) {
      return aCodePoints[i] - bCodePoints[i]
    }
  }
  return aCodePoints.length - bCodePoints.length
}

/**
 * Recursively sort object keys for RFC 8785 JCS compliance.
 * Validates all values according to signature-protocol.md requirements:
 * - No undefined values
 * - Numbers must be safe integers (no floats, no NaN/Infinity)
 * - Keys sorted by Unicode code point order
 *
 * @param value Value to sort and validate
 * @returns Sorted value
 * @throws Error if value contains JCS-invalid data
 */
function sortObjectKeys(value: unknown): unknown {
  // JCS compliance: reject undefined
  if (value === undefined) {
    throw new Error('JCS error: undefined values not allowed')
  }
  // JCS compliance: validate numbers
  if (typeof value === 'number') {
    validateJcsNumber(value)
    return value
  }
  if (value === null || typeof value !== 'object') {
    return value
  }
  if (Array.isArray(value)) {
    return value.map(sortObjectKeys)
  }
  const sorted: Record<string, unknown> = {}
  // Sort keys by Unicode code point order (RFC 8785 requirement)
  const keys = Object.keys(value as Record<string, unknown>).sort(compareByCodePoint)
  for (const key of keys) {
    sorted[key] = sortObjectKeys((value as Record<string, unknown>)[key])
  }
  return sorted
}

/**
 * Canonicalize an object to bytes using RFC 8785 JSON Canonicalization Scheme
 * (recursively sorted keys, no whitespace)
 *
 * @param obj Object to canonicalize
 * @returns Canonical JSON encoded as UTF-8 bytes
 * @throws Error if object contains undefined or non-finite numbers
 */
export function canonicalizeBytes(obj: Record<string, unknown>): Uint8Array {
  const sorted = sortObjectKeys(obj) as Record<string, unknown>
  const json = JSON.stringify(sorted)
  return new TextEncoder().encode(json)
}

/**
 * Build signature message with signature protocol format
 *
 * Per spec: All signatures should use the signature protocol format with
 * canonicalized JSON including protocol, version, and action fields.
 *
 * @param action Signature action (from SIGNATURE_ACTION)
 * @param payload Additional fields to include in the signature message
 * @returns Canonicalized signature message as bytes
 */
export function buildSignatureMessage(
  action: SignatureAction,
  payload: Record<string, unknown>
): Uint8Array {
  return canonicalizeBytes({
    ...SIGNATURE_PROTOCOL,
    action,
    ...payload,
  })
}
