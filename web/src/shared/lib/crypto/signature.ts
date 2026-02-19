/**
 * Signature Protocol Module
 *
 * Implements RFC 8785 JSON Canonicalization Scheme (JCS) for signature
 * message construction. Used for PoP, device approval, trust transfer,
 * and document update signatures.
 *
 * RFC 8785 JCS rules:
 * - Object properties sorted by Unicode code point order
 * - No whitespace
 * - UTF-8 encoded
 * - Binary data as base64url strings
 * - Numbers must be safe integers (no floats)
 */

/**
 * Signature protocol constants
 */
export const SIGNATURE_PROTOCOL = {
  protocol: 'doclock-v1',
  version: 1,
} as const

/**
 * Signature action constants
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
 * Validate number for JCS compliance:
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
 * Validates all values for JCS compliance:
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
 * All signatures use the signature protocol format with
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
