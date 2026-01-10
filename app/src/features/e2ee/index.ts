/**
 * E2EE Feature Module
 *
 * End-to-End Encryption for RefMD.
 */

// Crypto primitives (explicit exports to avoid conflicts)
export {
  // Sodium
  getSodium,
  isSodiumReady,
  type Sodium,
  // XChaCha20
  encrypt,
  decrypt,
  encryptDek,
  decryptDek,
  encryptString,
  decryptString,
  generateKey,
  generateNonce,
  NONCE_SIZE,
  KEY_SIZE,
  TAG_SIZE,
  type EncryptResult,
  // Ed25519
  sign,
  verify,
  signToBase64,
  verifyFromBase64,
  generateSigningKeyPair,
  buildSigningMessage,
  SIGNATURE_DOMAINS,
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  SIGNATURE_SIZE,
  type Ed25519KeyPair,
  type SigningMessage,
  type SignatureDomain,
  // Canonicalize
  canonicalize,
  canonicalizeAndToBase64,
  fromBase64Json,
  toBase64,
  fromBase64,
  // HKDF
  hkdfDeriveKey,
  hkdfGenerateMasterKey,
  HKDF_CONTEXTS,
  SUBKEY_IDS,
  MASTER_KEY_SIZE,
  MIN_KEY_SIZE,
  MAX_KEY_SIZE,
  // Argon2
  argon2DeriveKey,
  argon2DeriveKeyWithNewSalt,
  argon2GenerateSalt,
  isArgon2Supported,
  DEFAULT_ARGON2_PARAMS,
  ARGON2_SALT_SIZE,
  // Note: Argon2Params is exported from types
  // PBKDF2
  pbkdf2DeriveKey,
  pbkdf2DeriveKeyWithNewSalt,
  pbkdf2GenerateSalt,
  PBKDF2_DEFAULT_ITERATIONS,
  PBKDF2_SALT_SIZE,
  // ECDH
  generateEcdhKeyPair,
  getEcdhPublicKey,
  computeSharedSecret,
  deriveSharedKey,
  encryptKeyForRecipient,
  decryptKeyFromSender,
  isValidEcdhPublicKey,
  ECDH_PRIVATE_KEY_SIZE,
  ECDH_PUBLIC_KEY_SIZE,
  SHARED_SECRET_SIZE,
  // Note: EcdhKeyPair is exported from types
  // BIP39
  generateRecoveryKey,
  validateRecoveryKey,
  recoveryKeyToUmk,
  umkToRecoveryKey,
  getWordsAtIndices,
  verifyWords,
  generateVerificationIndices,
  getWordList,
  WORD_COUNT,
  ENTROPY_BITS,
  ENTROPY_BYTES,
} from './lib/crypto'

// Type definitions
export * from './lib/types'

// Key management (explicit exports to avoid conflicts)
export {
  // KeyManager
  KeyManager,
  getKeyManager,
  resetKeyManager,
  SessionLockedError,
  KeyNotFoundError,
  type E2EESetupResult,
  type EncryptedKeysBundle,
  // KeyStore
  KeyStore,
  getKeyStore,
  type StoredKeys,
  // KeyCache
  KeyCache,
  KekCache,
  DekCache,
  getKekCache,
  getDekCache,
  clearAllCaches,
  DEFAULT_KEK_CACHE_SIZE,
  DEFAULT_DEK_CACHE_SIZE,
  // UMK
  generateUmk,
  deriveUmkFromPassphrase,
  restoreUmkFromRecoveryKey,
  verifyPassphrase,
  generateNewRecoveryKey,
  zeroUmk,
  UMK_SIZE,
  type UmkGenerationResult,
  // User Keys
  generateUserKeys,
  encryptUserKeys,
  decryptUserKeys,
  reEncryptUserKeys,
  getPublicKeysBase64,
  parsePublicKeysFromBase64,
  zeroUserKeys,
  type UserKeySet,
  type EncryptedUserKeys,
  // Workspace KEK
  generateWorkspaceKek,
  encryptKekForRecipient,
  decryptKek,
  decryptKekFromApiResponse,
  encodeKekForApi,
  getOrFetchKek,
  invalidateCachedKek,
  createKekForMember,
  KEK_SIZE,
  type EncryptedKekFromApi,
  // Document DEK
  generateDocumentDek,
  encryptDekWithKek,
  decryptDekWithKek,
  decryptDekFromApiResponse,
  encodeDekForApi,
  createEncryptedDekForApi,
  getOrFetchDek,
  invalidateCachedDek,
  invalidateWorkspaceDeks,
  reEncryptDek,
  DEK_SIZE,
  type EncryptedDekFromApi,
  // Share Keys
  generateShareKey,
  extractShareKeyFromFragment,
  deriveShareKeyFromPassword,
  createPasswordProtectedShareKey,
  encryptDekWithShareKey,
  decryptDekWithShareKey,
  buildShareUrl,
  parseSaltFromApi,
  encodeSaltForApi,
  hasShareKeyFragment,
  SHARE_KEY_SIZE,
  URL_FRAGMENT_PREFIX,
  type EncryptedShareKeyForApi,
} from './lib/keys'

// Hooks
export { useSecurityStatus, useNeedsSecuritySetup } from './hooks/useSecurityStatus'
export { useKeyManager } from './hooks/useKeyManager'
export { useServerBackup, type ServerBackup } from './hooks/useServerBackup'

// Context
export { E2EEProvider, useE2EE, type E2EEState } from './context/e2ee-context'

// UI Components
export {
  PassphraseInput,
  RecoveryKeyDisplay,
  RecoveryKeyVerify,
  MigrationProgress,
  SecuritySetupWizard,
  UnlockPrompt,
  RestorePrompt,
} from './ui'

// Document key helpers
export {
  createDocumentDek,
  createDocumentDekIfNeeded,
  isE2EEReady,
} from './lib/document-keys'
