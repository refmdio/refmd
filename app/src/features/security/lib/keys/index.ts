/**
 * E2EE Key Management Module
 *
 * This module provides all key management functionality for E2EE:
 * - KeyManager: Main entry point for all key operations
 * - KeyStore: IndexedDB storage for encrypted keys
 * - KeyCache: LRU cache for KEK/DEK
 * - Individual key modules for UMK, User Keys, KEK, DEK, Share Keys
 */

// Main KeyManager class
export {
  KeyManager,
  getKeyManager,
  resetKeyManager,
  SessionLockedError,
  KeyNotFoundError,
  type E2EESetupResult,
  type EncryptedKeysBundle,
} from './key-manager'

// Key Store (IndexedDB)
export {
  KeyStore,
  getKeyStore,
  type StoredKeys,
} from './key-store'

// Key Cache (LRU)
export {
  KeyCache,
  KekCache,
  DekCache,
  getKekCache,
  getDekCache,
  clearAllCaches,
  DEFAULT_KEK_CACHE_SIZE,
  DEFAULT_DEK_CACHE_SIZE,
} from './key-cache'

// UMK (User Master Key)
export {
  generateUmk,
  deriveUmkFromPassphrase,
  restoreUmkFromRecoveryKey,
  verifyPassphrase,
  generateNewRecoveryKey,
  validateRecoveryKey,
  zeroUmk,
  UMK_SIZE,
  type UmkGenerationResult,
} from './umk'

// User Keys (ECDH + Ed25519)
export {
  generateUserKeys,
  encryptUserKeys,
  decryptUserKeys,
  reEncryptUserKeys,
  getPublicKeysBase64,
  parsePublicKeysFromBase64,
  zeroUserKeys,
  type UserKeySet,
  type EncryptedUserKeys,
} from './user-keys'

// Workspace KEK
export {
  generateWorkspaceKek,
  encryptKekForRecipient,
  decryptKek,
  decryptKekFromApiResponse,
  encodeKekForApi,
  getOrFetchKek,
  invalidateCachedKek,
  createKekForMember,
  KEK_SIZE,
  type WorkspaceKek,
  type EncryptedKekFromApi,
} from './workspace-kek'

// Document DEK
export {
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
  type DocumentDek,
  type EncryptedDekFromApi,
} from './document-dek'

// Share Keys
export {
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
  type ShareKey,
  type EncryptedShareKeyForApi,
} from './share-key'

// Invitation KEK
export {
  deriveKeyFromInvitationToken,
  encryptKekForInvitation,
  decryptKekFromInvitation,
  encodeInvitationKekForApi,
  decodeInvitationKekFromApi,
} from './invitation-kek'
