/**
 * E2EE Error Types
 *
 * Error codes and types for E2EE operations.
 */

/** E2EE error codes */
export const E2EE_ERROR_CODES = {
  // Key errors (1xxx)
  KEY_NOT_FOUND: 'E2EE_KEY_NOT_FOUND',
  KEY_INVALID: 'E2EE_KEY_INVALID',
  KEY_EXPIRED: 'E2EE_KEY_EXPIRED',
  KEY_GENERATION_FAILED: 'E2EE_KEY_GENERATION_FAILED',
  KEY_DERIVATION_FAILED: 'E2EE_KEY_DERIVATION_FAILED',

  // Crypto errors (2xxx)
  ENCRYPTION_FAILED: 'E2EE_ENCRYPTION_FAILED',
  DECRYPTION_FAILED: 'E2EE_DECRYPTION_FAILED',
  SIGNATURE_INVALID: 'E2EE_SIGNATURE_INVALID',
  SIGNATURE_FAILED: 'E2EE_SIGNATURE_FAILED',
  NONCE_REUSE: 'E2EE_NONCE_REUSE',

  // Session errors (3xxx)
  SESSION_LOCKED: 'E2EE_SESSION_LOCKED',
  SESSION_EXPIRED: 'E2EE_SESSION_EXPIRED',
  PASSPHRASE_INVALID: 'E2EE_PASSPHRASE_INVALID',
  RECOVERY_KEY_INVALID: 'E2EE_RECOVERY_KEY_INVALID',

  // Setup errors (4xxx)
  SETUP_INCOMPLETE: 'E2EE_SETUP_INCOMPLETE',
  SETUP_FAILED: 'E2EE_SETUP_FAILED',
  MIGRATION_FAILED: 'E2EE_MIGRATION_FAILED',

  // Sync errors (5xxx)
  SYNC_CONFLICT: 'E2EE_SYNC_CONFLICT',
  SYNC_FAILED: 'E2EE_SYNC_FAILED',
  MESSAGE_INVALID: 'E2EE_MESSAGE_INVALID',

  // Storage errors (6xxx)
  STORAGE_FAILED: 'E2EE_STORAGE_FAILED',
  STORAGE_NOT_AVAILABLE: 'E2EE_STORAGE_NOT_AVAILABLE',

  // File errors (7xxx)
  FILE_FORMAT_INVALID: 'E2EE_FILE_FORMAT_INVALID',
  FILE_CORRUPTED: 'E2EE_FILE_CORRUPTED',

  // Network errors (8xxx)
  NETWORK_FAILED: 'E2EE_NETWORK_FAILED',
  SERVER_ERROR: 'E2EE_SERVER_ERROR',
} as const

export type E2EEErrorCode = typeof E2EE_ERROR_CODES[keyof typeof E2EE_ERROR_CODES]

/**
 * E2EE Error class
 */
export class E2EEError extends Error {
  readonly code: E2EEErrorCode
  readonly cause?: Error

  constructor(code: E2EEErrorCode, message: string, cause?: Error) {
    super(message)
    this.name = 'E2EEError'
    this.code = code
    this.cause = cause
  }

  /**
   * Check if this error is recoverable
   */
  isRecoverable(): boolean {
    switch (this.code) {
      case E2EE_ERROR_CODES.SESSION_LOCKED:
      case E2EE_ERROR_CODES.SESSION_EXPIRED:
      case E2EE_ERROR_CODES.PASSPHRASE_INVALID:
      case E2EE_ERROR_CODES.NETWORK_FAILED:
        return true
      default:
        return false
    }
  }

  /**
   * Get user-friendly error message
   */
  getUserMessage(): string {
    switch (this.code) {
      case E2EE_ERROR_CODES.SESSION_LOCKED:
        return 'Your session is locked. Please enter your passphrase to continue.'
      case E2EE_ERROR_CODES.PASSPHRASE_INVALID:
        return 'The passphrase you entered is incorrect.'
      case E2EE_ERROR_CODES.RECOVERY_KEY_INVALID:
        return 'The recovery key is invalid. Please check and try again.'
      case E2EE_ERROR_CODES.DECRYPTION_FAILED:
        return 'Failed to decrypt the content. The data may be corrupted.'
      case E2EE_ERROR_CODES.SIGNATURE_INVALID:
        return 'The message signature is invalid. The content may have been tampered with.'
      case E2EE_ERROR_CODES.KEY_NOT_FOUND:
        return 'The encryption key was not found. You may not have access to this content.'
      case E2EE_ERROR_CODES.SETUP_INCOMPLETE:
        return 'E2EE setup is not complete. Please complete the setup process.'
      case E2EE_ERROR_CODES.NETWORK_FAILED:
        return 'Network error. Please check your connection and try again.'
      default:
        return this.message
    }
  }
}

/**
 * Create an E2EE error
 */
export function createE2EEError(
  code: E2EEErrorCode,
  message: string,
  cause?: Error
): E2EEError {
  return new E2EEError(code, message, cause)
}

/**
 * Check if an error is an E2EE error
 */
export function isE2EEError(error: unknown): error is E2EEError {
  return error instanceof E2EEError
}

/**
 * Wrap an error as an E2EE error
 */
export function wrapError(
  code: E2EEErrorCode,
  error: unknown,
  fallbackMessage: string
): E2EEError {
  if (error instanceof Error) {
    return new E2EEError(code, error.message, error)
  }
  return new E2EEError(code, fallbackMessage)
}
