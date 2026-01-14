/**
 * E2EE Error Types
 *
 * Error codes and types for cryptographic operations.
 */

/** Error codes */
export const ERROR_CODES = {
  // Key errors
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  KEY_INVALID: 'KEY_INVALID',
  KEY_EXPIRED: 'KEY_EXPIRED',
  KEY_GENERATION_FAILED: 'KEY_GENERATION_FAILED',
  KEY_DERIVATION_FAILED: 'KEY_DERIVATION_FAILED',

  // Crypto errors
  ENCRYPTION_FAILED: 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  SIGNATURE_FAILED: 'SIGNATURE_FAILED',
  NONCE_REUSE: 'NONCE_REUSE',

  // Session errors
  SESSION_LOCKED: 'SESSION_LOCKED',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  PASSPHRASE_INVALID: 'PASSPHRASE_INVALID',
  RECOVERY_KEY_INVALID: 'RECOVERY_KEY_INVALID',

  // Setup errors
  SETUP_INCOMPLETE: 'SETUP_INCOMPLETE',
  SETUP_FAILED: 'SETUP_FAILED',
  MIGRATION_FAILED: 'MIGRATION_FAILED',

  // Sync errors
  SYNC_CONFLICT: 'SYNC_CONFLICT',
  SYNC_FAILED: 'SYNC_FAILED',
  SYNC_TIMEOUT: 'SYNC_TIMEOUT',
  MESSAGE_INVALID: 'MESSAGE_INVALID',

  // Storage errors
  STORAGE_FAILED: 'STORAGE_FAILED',
  STORAGE_NOT_AVAILABLE: 'STORAGE_NOT_AVAILABLE',

  // File errors
  FILE_FORMAT_INVALID: 'FILE_FORMAT_INVALID',
  FILE_CORRUPTED: 'FILE_CORRUPTED',

  // Network errors
  NETWORK_FAILED: 'NETWORK_FAILED',
  SERVER_ERROR: 'SERVER_ERROR',
} as const

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES]

/** Error categories for display/handling decisions */
export const ERROR_CATEGORY = {
  /** Critical errors requiring modal dialog (key/decryption failures) */
  CRITICAL: 'critical',
  /** High severity errors shown as banner (sync/storage failures) */
  HIGH: 'high',
  /** Medium severity errors shown as toast (temporary network issues) */
  MEDIUM: 'medium',
  /** Low severity errors logged only (internal errors) */
  LOW: 'low',
} as const

export type ErrorCategory = (typeof ERROR_CATEGORY)[keyof typeof ERROR_CATEGORY]

/** Error context (excludes sensitive data) */
export interface ErrorContext {
  documentId?: string
  workspaceId?: string
  operation?: string
}

/** Get error category from error code */
function getErrorCategory(code: ErrorCode): ErrorCategory {
  switch (code) {
    // Critical: key and crypto failures
    case ERROR_CODES.KEY_NOT_FOUND:
    case ERROR_CODES.KEY_INVALID:
    case ERROR_CODES.KEY_DERIVATION_FAILED:
    case ERROR_CODES.DECRYPTION_FAILED:
    case ERROR_CODES.SIGNATURE_INVALID:
    case ERROR_CODES.FILE_CORRUPTED:
      return ERROR_CATEGORY.CRITICAL

    // High: sync and storage failures
    case ERROR_CODES.SYNC_CONFLICT:
    case ERROR_CODES.SYNC_FAILED:
    case ERROR_CODES.STORAGE_FAILED:
    case ERROR_CODES.STORAGE_NOT_AVAILABLE:
    case ERROR_CODES.SETUP_FAILED:
    case ERROR_CODES.MIGRATION_FAILED:
      return ERROR_CATEGORY.HIGH

    // Medium: temporary/recoverable errors
    case ERROR_CODES.NETWORK_FAILED:
    case ERROR_CODES.SYNC_TIMEOUT:
    case ERROR_CODES.SESSION_LOCKED:
    case ERROR_CODES.SESSION_EXPIRED:
    case ERROR_CODES.PASSPHRASE_INVALID:
    case ERROR_CODES.RECOVERY_KEY_INVALID:
      return ERROR_CATEGORY.MEDIUM

    // Low: everything else
    default:
      return ERROR_CATEGORY.LOW
  }
}

/** Error messages by locale */
const ERROR_MESSAGES: Record<ErrorCode, { en: string; ja: string }> = {
  [ERROR_CODES.KEY_NOT_FOUND]: {
    en: 'The encryption key was not found. You may not have access to this content.',
    ja: '暗号化キーが見つかりません。このコンテンツへのアクセス権限がない可能性があります。',
  },
  [ERROR_CODES.KEY_INVALID]: {
    en: 'The encryption key is invalid.',
    ja: '暗号化キーが無効です。',
  },
  [ERROR_CODES.KEY_EXPIRED]: {
    en: 'The encryption key has expired.',
    ja: '暗号化キーの有効期限が切れています。',
  },
  [ERROR_CODES.KEY_GENERATION_FAILED]: {
    en: 'Failed to generate encryption key.',
    ja: '暗号化キーの生成に失敗しました。',
  },
  [ERROR_CODES.KEY_DERIVATION_FAILED]: {
    en: 'Failed to derive encryption key.',
    ja: '暗号化キーの導出に失敗しました。',
  },
  [ERROR_CODES.ENCRYPTION_FAILED]: {
    en: 'Failed to encrypt the content.',
    ja: 'コンテンツの暗号化に失敗しました。',
  },
  [ERROR_CODES.DECRYPTION_FAILED]: {
    en: 'Failed to decrypt the content. The data may be corrupted.',
    ja: 'コンテンツの復号に失敗しました。データが破損している可能性があります。',
  },
  [ERROR_CODES.SIGNATURE_INVALID]: {
    en: 'The message signature is invalid. The content may have been tampered with.',
    ja: 'メッセージの署名が無効です。コンテンツが改ざんされている可能性があります。',
  },
  [ERROR_CODES.SIGNATURE_FAILED]: {
    en: 'Failed to sign the message.',
    ja: 'メッセージへの署名に失敗しました。',
  },
  [ERROR_CODES.NONCE_REUSE]: {
    en: 'Security error: nonce reuse detected.',
    ja: 'セキュリティエラー: ナンスの再利用が検出されました。',
  },
  [ERROR_CODES.SESSION_LOCKED]: {
    en: 'Your session is locked. Please enter your passphrase to continue.',
    ja: 'セッションがロックされています。パスフレーズを入力してください。',
  },
  [ERROR_CODES.SESSION_EXPIRED]: {
    en: 'Your session has expired. Please log in again.',
    ja: 'セッションの有効期限が切れました。再度ログインしてください。',
  },
  [ERROR_CODES.PASSPHRASE_INVALID]: {
    en: 'The passphrase you entered is incorrect.',
    ja: '入力されたパスフレーズが正しくありません。',
  },
  [ERROR_CODES.RECOVERY_KEY_INVALID]: {
    en: 'The recovery key is invalid. Please check and try again.',
    ja: 'リカバリーキーが無効です。確認してもう一度お試しください。',
  },
  [ERROR_CODES.SETUP_INCOMPLETE]: {
    en: 'Security setup is not complete. Please complete the setup process.',
    ja: 'セキュリティのセットアップが完了していません。セットアップを完了してください。',
  },
  [ERROR_CODES.SETUP_FAILED]: {
    en: 'Failed to complete security setup.',
    ja: 'セキュリティのセットアップに失敗しました。',
  },
  [ERROR_CODES.MIGRATION_FAILED]: {
    en: 'Failed to migrate data.',
    ja: 'データの移行に失敗しました。',
  },
  [ERROR_CODES.SYNC_CONFLICT]: {
    en: 'Sync conflict detected. Your changes may conflict with other users.',
    ja: '同期の競合が検出されました。他のユーザーの変更と競合している可能性があります。',
  },
  [ERROR_CODES.SYNC_FAILED]: {
    en: 'Failed to sync changes.',
    ja: '変更の同期に失敗しました。',
  },
  [ERROR_CODES.SYNC_TIMEOUT]: {
    en: 'Sync timed out. Please try again.',
    ja: '同期がタイムアウトしました。もう一度お試しください。',
  },
  [ERROR_CODES.MESSAGE_INVALID]: {
    en: 'Received an invalid message.',
    ja: '無効なメッセージを受信しました。',
  },
  [ERROR_CODES.STORAGE_FAILED]: {
    en: 'Failed to access storage.',
    ja: 'ストレージへのアクセスに失敗しました。',
  },
  [ERROR_CODES.STORAGE_NOT_AVAILABLE]: {
    en: 'Storage is not available.',
    ja: 'ストレージが利用できません。',
  },
  [ERROR_CODES.FILE_FORMAT_INVALID]: {
    en: 'Invalid file format.',
    ja: 'ファイル形式が無効です。',
  },
  [ERROR_CODES.FILE_CORRUPTED]: {
    en: 'The file appears to be corrupted.',
    ja: 'ファイルが破損しているようです。',
  },
  [ERROR_CODES.NETWORK_FAILED]: {
    en: 'Network error. Please check your connection and try again.',
    ja: 'ネットワークエラー。接続を確認してもう一度お試しください。',
  },
  [ERROR_CODES.SERVER_ERROR]: {
    en: 'Server error. Please try again later.',
    ja: 'サーバーエラー。しばらくしてからもう一度お試しください。',
  },
}

/**
 * Crypto Error class
 */
export class CryptoError extends Error {
  readonly code: ErrorCode
  readonly category: ErrorCategory
  readonly cause?: Error
  readonly context?: ErrorContext

  constructor(
    code: ErrorCode,
    message: string,
    options?: {
      cause?: Error
      context?: ErrorContext
    }
  ) {
    super(message)
    this.name = 'CryptoError'
    this.code = code
    this.category = getErrorCategory(code)
    this.cause = options?.cause
    this.context = options?.context
  }

  /**
   * Check if this error is recoverable
   */
  isRecoverable(): boolean {
    switch (this.code) {
      case ERROR_CODES.SESSION_LOCKED:
      case ERROR_CODES.SESSION_EXPIRED:
      case ERROR_CODES.PASSPHRASE_INVALID:
      case ERROR_CODES.RECOVERY_KEY_INVALID:
      case ERROR_CODES.NETWORK_FAILED:
      case ERROR_CODES.SYNC_TIMEOUT:
        return true
      default:
        return false
    }
  }

  /**
   * Get user-friendly error message (default: English)
   */
  getUserMessage(): string {
    return this.getLocalizedMessage('en')
  }

  /**
   * Get localized user-friendly error message
   */
  getLocalizedMessage(locale: 'en' | 'ja' = 'en'): string {
    const messages = ERROR_MESSAGES[this.code]
    if (messages) {
      return messages[locale]
    }
    return this.message
  }
}

/**
 * Create a crypto error
 */
export function createError(
  code: ErrorCode,
  message: string,
  options?: {
    cause?: Error
    context?: ErrorContext
  }
): CryptoError {
  return new CryptoError(code, message, options)
}

/**
 * Check if an error is a CryptoError
 */
export function isCryptoError(error: unknown): error is CryptoError {
  return error instanceof CryptoError
}

/**
 * Wrap an error as a CryptoError
 */
export function wrapError(
  code: ErrorCode,
  error: unknown,
  fallbackMessage: string,
  context?: ErrorContext
): CryptoError {
  if (error instanceof Error) {
    return new CryptoError(code, error.message, { cause: error, context })
  }
  return new CryptoError(code, fallbackMessage, { context })
}

// Legacy aliases for backward compatibility during migration
/** @deprecated Use ERROR_CODES instead */
export const E2EE_ERROR_CODES = ERROR_CODES
/** @deprecated Use ErrorCode instead */
export type E2EEErrorCode = ErrorCode
/** @deprecated Use CryptoError instead */
export const E2EEError = CryptoError
/** @deprecated Use createError instead */
export const createE2EEError = createError
/** @deprecated Use isCryptoError instead */
export const isE2EEError = isCryptoError
