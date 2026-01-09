/**
 * KeyManager - Central key management for E2EE
 *
 * This is the main entry point for all key operations.
 * It coordinates between the KeyStore, KeyCache, and individual key modules.
 */

import { KeyStore, getKeyStore, type StoredKeys } from './key-store'
import { clearAllCaches } from './key-cache'
import {
  generateUmk,
  deriveUmkFromPassphrase,
  restoreUmkFromRecoveryKey,
  verifyPassphrase,
  zeroUmk,
} from './umk'
import {
  generateUserKeys,
  encryptUserKeys,
  decryptUserKeys,
  getPublicKeysBase64,
  zeroUserKeys,
  type UserKeySet,
} from './user-keys'
import {
  generateWorkspaceKek,
  getOrFetchKek,
  invalidateCachedKek,
  createKekForMember,
  decryptKekFromApiResponse,
} from './workspace-kek'
import {
  generateDocumentDek,
  getOrFetchDek,
  invalidateCachedDek,
  invalidateWorkspaceDeks,
  createEncryptedDekForApi,
  decryptDekFromApiResponse,
} from './document-dek'
import {
  generateShareKey,
  extractShareKeyFromFragment,
  deriveShareKeyFromPassword,
  createPasswordProtectedShareKey,
  encryptDekWithShareKey,
  decryptDekWithShareKey,
} from './share-key'

/** E2EE Setup result */
export interface E2EESetupResult {
  /** BIP39 recovery key (24 words) - must be shown to user */
  recoveryKey: string
  /** Public keys to register with server */
  publicKeys: {
    ecdhPublicKey: string
    signingPublicKey: string
  }
  /** Salt used for passphrase derivation */
  salt: Uint8Array
  /** KDF type used */
  kdf: 'argon2id' | 'pbkdf2'
  /** KDF parameters */
  kdfParams: { memory?: number; iterations: number; parallelism?: number }
}

/** Session lock error */
export class SessionLockedError extends Error {
  constructor() {
    super('Session is locked. Please unlock with passphrase.')
    this.name = 'SessionLockedError'
  }
}

/** Key not found error */
export class KeyNotFoundError extends Error {
  constructor(keyType: string, id: string) {
    super(`${keyType} not found for ${id}`)
    this.name = 'KeyNotFoundError'
  }
}

/**
 * KeyManager - Singleton class for managing E2EE keys
 */
export class KeyManager {
  private keyStore: KeyStore
  private umk: Uint8Array | null = null
  private userKeys: UserKeySet | null = null
  private _isInitialized = false

  constructor(keyStore?: KeyStore) {
    this.keyStore = keyStore ?? getKeyStore()
  }

  /**
   * Initialize the KeyManager.
   * Must be called before any other operations.
   */
  async initialize(): Promise<void> {
    if (this._isInitialized) return
    await this.keyStore.initialize()
    this._isInitialized = true
  }

  /**
   * Check if KeyManager is initialized.
   */
  get isInitialized(): boolean {
    return this._isInitialized
  }

  /**
   * Check if session is unlocked.
   */
  get isUnlocked(): boolean {
    return this.umk !== null && this.userKeys !== null
  }

  /**
   * Check if user has E2EE keys set up.
   */
  async hasKeys(): Promise<boolean> {
    await this.ensureInitialized()
    return this.keyStore.hasKeys()
  }

  // ============================================
  // E2EE Setup
  // ============================================

  /**
   * Set up E2EE for a new user or existing user migrating.
   *
   * @param passphrase - User's passphrase (min 8 characters)
   * @returns Setup result with recovery key and public keys
   */
  async setupE2EE(passphrase: string): Promise<E2EESetupResult> {
    await this.ensureInitialized()

    // Generate UMK from passphrase
    const umkResult = await generateUmk(passphrase)

    // Generate user key pairs
    const userKeys = await generateUserKeys()

    // Encrypt user keys with UMK
    const encryptedKeys = await encryptUserKeys(userKeys, umkResult.umk)

    // Store in IndexedDB
    const kdfParams = umkResult.kdf === 'argon2id'
      ? {
          type: 'argon2id' as const,
          memory: (umkResult.kdfParams as { memory: number; iterations: number; parallelism: number }).memory,
          iterations: (umkResult.kdfParams as { memory: number; iterations: number; parallelism: number }).iterations,
          parallelism: (umkResult.kdfParams as { memory: number; iterations: number; parallelism: number }).parallelism,
        }
      : {
          type: 'pbkdf2' as const,
          iterations: (umkResult.kdfParams as { iterations: number }).iterations,
        }

    const storedKeys: StoredKeys = {
      ...encryptedKeys,
      salt: umkResult.salt,
      kdf: umkResult.kdf,
      kdfParams,
      createdAt: Date.now(),
    }

    await this.keyStore.saveKeys(storedKeys)

    // Keep UMK and keys in memory
    this.umk = umkResult.umk
    this.userKeys = userKeys

    // Get public keys for server registration
    const publicKeys = await getPublicKeysBase64(userKeys)

    return {
      recoveryKey: umkResult.recoveryKey,
      publicKeys,
      salt: umkResult.salt,
      kdf: umkResult.kdf,
      kdfParams: umkResult.kdfParams,
    }
  }

  // ============================================
  // Unlock / Lock
  // ============================================

  /**
   * Unlock the session with a passphrase.
   *
   * @param passphrase - User's passphrase
   * @throws Error if passphrase is incorrect
   */
  async unlockWithPassphrase(passphrase: string): Promise<void> {
    await this.ensureInitialized()

    const storedKeys = await this.keyStore.loadKeys()
    if (!storedKeys) {
      throw new Error('No E2EE keys found. Please set up E2EE first.')
    }

    // Derive UMK from passphrase
    const umk = await deriveUmkFromPassphrase(
      passphrase,
      storedKeys.salt,
      storedKeys.kdf,
      storedKeys.kdfParams
    )

    // Try to decrypt user keys to verify passphrase
    try {
      const userKeys = await decryptUserKeys(storedKeys, umk)
      this.umk = umk
      this.userKeys = userKeys
    } catch {
      // Zero out UMK on failure
      umk.fill(0)
      throw new Error('Incorrect passphrase')
    }
  }

  /**
   * Unlock the session with a recovery key.
   *
   * @param recoveryKey - BIP39 mnemonic (24 words)
   * @throws Error if recovery key is invalid
   */
  async unlockWithRecoveryKey(recoveryKey: string): Promise<void> {
    await this.ensureInitialized()

    const storedKeys = await this.keyStore.loadKeys()
    if (!storedKeys) {
      throw new Error('No E2EE keys found. Please set up E2EE first.')
    }

    // Restore UMK from recovery key
    const umk = restoreUmkFromRecoveryKey(recoveryKey)

    // Try to decrypt user keys to verify recovery key
    try {
      const userKeys = await decryptUserKeys(storedKeys, umk)
      this.umk = umk
      this.userKeys = userKeys
    } catch {
      // Zero out UMK on failure
      umk.fill(0)
      throw new Error('Incorrect recovery key')
    }
  }

  /**
   * Lock the session - clears all keys from memory.
   */
  lock(): void {
    if (this.umk) {
      zeroUmk(this.umk)
      this.umk = null
    }

    if (this.userKeys) {
      zeroUserKeys(this.userKeys)
      this.userKeys = null
    }

    // Clear all cached KEKs and DEKs
    clearAllCaches()
  }

  /**
   * Verify if a passphrase is correct without unlocking.
   */
  async verifyPassphrase(passphrase: string): Promise<boolean> {
    await this.ensureInitialized()

    const storedKeys = await this.keyStore.loadKeys()
    if (!storedKeys) {
      return false
    }

    return verifyPassphrase(passphrase, storedKeys)
  }

  // ============================================
  // User Keys
  // ============================================

  /**
   * Get the current user's ECDH key pair.
   */
  getEcdhKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    this.ensureUnlocked()
    return {
      publicKey: this.userKeys!.ecdh.publicKey,
      privateKey: this.userKeys!.ecdh.privateKey,
    }
  }

  /**
   * Get the current user's signing key pair.
   */
  getSigningKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    this.ensureUnlocked()
    return {
      publicKey: this.userKeys!.signing.publicKey,
      privateKey: this.userKeys!.signing.privateKey,
    }
  }

  /**
   * Get public keys as Base64 for API requests.
   */
  async getPublicKeysBase64(): Promise<{ ecdhPublicKey: string; signingPublicKey: string }> {
    this.ensureUnlocked()
    return getPublicKeysBase64(this.userKeys!)
  }

  // ============================================
  // Workspace KEK
  // ============================================

  /**
   * Generate a new workspace KEK.
   */
  async generateWorkspaceKek(): Promise<Uint8Array> {
    return generateWorkspaceKek()
  }

  /**
   * Encrypt a KEK for a recipient.
   */
  async encryptKekForRecipient(
    kek: Uint8Array,
    recipientPublicKey: Uint8Array
  ): Promise<string> {
    return createKekForMember(kek, recipientPublicKey)
  }

  /**
   * Get a workspace KEK (from cache or API).
   *
   * @param workspaceId - Workspace ID
   * @param fetchFn - Function to fetch encrypted KEK from API
   */
  async getWorkspaceKek(
    workspaceId: string,
    fetchFn: () => Promise<string>
  ): Promise<Uint8Array> {
    this.ensureUnlocked()
    return getOrFetchKek(workspaceId, this.userKeys!.ecdh.privateKey, fetchFn)
  }

  /**
   * Decrypt a KEK directly from API response.
   */
  async decryptKek(encryptedKekBase64: string): Promise<Uint8Array> {
    this.ensureUnlocked()
    return decryptKekFromApiResponse(this.userKeys!.ecdh.privateKey, encryptedKekBase64)
  }

  /**
   * Invalidate cached KEK.
   */
  invalidateKekCache(workspaceId: string): void {
    invalidateCachedKek(workspaceId)
  }

  // ============================================
  // Document DEK
  // ============================================

  /**
   * Generate a new document DEK.
   */
  async generateDocumentDek(): Promise<Uint8Array> {
    return generateDocumentDek()
  }

  /**
   * Create an encrypted DEK for API storage.
   */
  async createEncryptedDek(
    dek: Uint8Array,
    kek: Uint8Array
  ): Promise<{ encryptedDek: string; nonce: string }> {
    return createEncryptedDekForApi(dek, kek)
  }

  /**
   * Get a document DEK (from cache or API).
   *
   * @param documentId - Document ID
   * @param kek - Workspace KEK
   * @param fetchFn - Function to fetch encrypted DEK from API
   */
  async getDocumentDek(
    documentId: string,
    kek: Uint8Array,
    fetchFn: () => Promise<{ encryptedDek: string; nonce: string }>
  ): Promise<Uint8Array> {
    return getOrFetchDek(documentId, kek, fetchFn)
  }

  /**
   * Decrypt a DEK directly from API response.
   */
  async decryptDek(
    encryptedDekBase64: string,
    nonceBase64: string,
    kek: Uint8Array
  ): Promise<Uint8Array> {
    return decryptDekFromApiResponse(encryptedDekBase64, nonceBase64, kek)
  }

  /**
   * Invalidate cached DEK.
   */
  invalidateDekCache(documentId: string): void {
    invalidateCachedDek(documentId)
  }

  /**
   * Invalidate all DEKs for a workspace.
   */
  invalidateWorkspaceDeksCache(documentIds: string[]): void {
    invalidateWorkspaceDeks(documentIds)
  }

  // ============================================
  // Share Keys
  // ============================================

  /**
   * Generate a share key for URL fragment mode.
   */
  async generateShareKey(): Promise<{ key: Uint8Array; fragment: string }> {
    return generateShareKey()
  }

  /**
   * Extract share key from URL fragment.
   */
  async extractShareKeyFromFragment(fragment: string): Promise<Uint8Array | null> {
    return extractShareKeyFromFragment(fragment)
  }

  /**
   * Derive share key from password.
   */
  async deriveShareKeyFromPassword(
    password: string,
    salt: Uint8Array
  ): Promise<Uint8Array> {
    return deriveShareKeyFromPassword(password, salt)
  }

  /**
   * Create a password-protected share key.
   */
  async createPasswordProtectedShareKey(
    password: string
  ): Promise<{ key: Uint8Array; salt: Uint8Array }> {
    return createPasswordProtectedShareKey(password)
  }

  /**
   * Encrypt a DEK with a share key.
   */
  async encryptDekWithShareKey(
    dek: Uint8Array,
    shareKey: Uint8Array
  ): Promise<{ encryptedDek: string; nonce: string }> {
    return encryptDekWithShareKey(dek, shareKey)
  }

  /**
   * Decrypt a DEK with a share key.
   */
  async decryptDekWithShareKey(
    encryptedDekBase64: string,
    nonceBase64: string,
    shareKey: Uint8Array
  ): Promise<Uint8Array> {
    return decryptDekWithShareKey(encryptedDekBase64, nonceBase64, shareKey)
  }

  // ============================================
  // Password Change
  // ============================================

  /**
   * Change the passphrase.
   * Session must be unlocked.
   *
   * @param newPassphrase - New passphrase
   * @returns New recovery key
   */
  async changePassphrase(newPassphrase: string): Promise<string> {
    this.ensureUnlocked()

    // Generate new UMK from new passphrase
    const umkResult = await generateUmk(newPassphrase)

    // Re-encrypt user keys with new UMK
    const encryptedKeys = await encryptUserKeys(this.userKeys!, umkResult.umk)

    // Build KDF params with type discriminator
    const kdfParams = umkResult.kdf === 'argon2id'
      ? {
          type: 'argon2id' as const,
          memory: (umkResult.kdfParams as { memory: number; iterations: number; parallelism: number }).memory,
          iterations: (umkResult.kdfParams as { memory: number; iterations: number; parallelism: number }).iterations,
          parallelism: (umkResult.kdfParams as { memory: number; iterations: number; parallelism: number }).parallelism,
        }
      : {
          type: 'pbkdf2' as const,
          iterations: (umkResult.kdfParams as { iterations: number }).iterations,
        }

    // Store updated keys
    const storedKeys: StoredKeys = {
      ...encryptedKeys,
      salt: umkResult.salt,
      kdf: umkResult.kdf,
      kdfParams,
      createdAt: Date.now(),
    }

    await this.keyStore.saveKeys(storedKeys)

    // Zero out old UMK
    if (this.umk) {
      zeroUmk(this.umk)
    }

    // Update session with new UMK
    this.umk = umkResult.umk

    return umkResult.recoveryKey
  }

  // ============================================
  // Utility
  // ============================================

  /**
   * Clear all stored keys (for account deletion or reset).
   */
  async clearAllKeys(): Promise<void> {
    this.lock()
    await this.keyStore.clear()
    this._isInitialized = false
  }

  /**
   * Get UMK (for migration or backup operations).
   * Use with caution - UMK should not be exposed.
   */
  getUmk(): Uint8Array {
    this.ensureUnlocked()
    return this.umk!
  }

  // ============================================
  // Private Helpers
  // ============================================

  private async ensureInitialized(): Promise<void> {
    if (!this._isInitialized) {
      await this.initialize()
    }
  }

  private ensureUnlocked(): void {
    if (!this.isUnlocked) {
      throw new SessionLockedError()
    }
  }
}

// Singleton instance
let keyManagerInstance: KeyManager | null = null

/**
 * Get the singleton KeyManager instance.
 */
export function getKeyManager(): KeyManager {
  if (!keyManagerInstance) {
    keyManagerInstance = new KeyManager()
  }
  return keyManagerInstance
}

/**
 * Reset the singleton instance (for testing).
 */
export function resetKeyManager(): void {
  if (keyManagerInstance) {
    keyManagerInstance.lock()
  }
  keyManagerInstance = null
}
