/**
 * KeyManager - Central key management for E2EE
 *
 * This is the main entry point for all key operations.
 * It coordinates between the KeyStore, KeyCache, and individual key modules.
 */

import { toBase64, fromBase64 } from '../crypto'
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
  encryptKekForRecipient,
  encodeKekForApi,
} from './workspace-kek'
import {
  encryptKekForInvitation,
  decryptKekFromInvitation,
  encodeInvitationKekForApi,
  decodeInvitationKekFromApi,
} from './invitation-kek'
import { getKekCache } from './key-cache'
import { storeWorkspaceKey, getMyWorkspaceKey } from '@/shared/api/client'
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

/** Encrypted keys data for server storage */
export interface EncryptedKeysBundle {
  /** Encrypted ECDH private key (base64) */
  encryptedEcdhPrivateKey: string
  /** Nonce for ECDH key encryption (base64) */
  encryptedEcdhPrivateKeyNonce: string
  /** Encrypted signing private key (base64) */
  encryptedSigningPrivateKey: string
  /** Nonce for signing key encryption (base64) */
  encryptedSigningPrivateKeyNonce: string
  /** ECDH public key (base64) */
  ecdhPublicKey: string
  /** Signing public key (base64) */
  signingPublicKey: string
}

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
  /** Encrypted keys bundle for server storage */
  encryptedKeysBundle: EncryptedKeysBundle
}

/** Session lock error */
export class SessionLockedError extends Error {
  constructor() {
    super('Session is locked. Please unlock with passphrase.')
    this.name = 'SessionLockedError'
  }
}

/** KDF parameters with type discriminator */
type KdfParams =
  | { type: 'argon2id'; memory: number; iterations: number; parallelism: number }
  | { type: 'pbkdf2'; iterations: number }

/**
 * Build KDF parameters from server backup data.
 * Handles null/undefined values with sensible defaults.
 */
function buildKdfParams(
  kdfType: 'argon2id' | 'pbkdf2',
  rawParams: { memory?: number | null; iterations?: number | null; parallelism?: number | null }
): KdfParams {
  if (kdfType === 'argon2id') {
    return {
      type: 'argon2id',
      memory: rawParams.memory ?? 65536,
      iterations: rawParams.iterations ?? 3,
      parallelism: rawParams.parallelism ?? 4,
    }
  }
  return {
    type: 'pbkdf2',
    iterations: rawParams.iterations ?? 600000,
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
  private unlockListeners = new Set<() => void>()

  constructor(keyStore?: KeyStore) {
    this.keyStore = keyStore ?? getKeyStore()
  }

  /**
   * Subscribe to unlock state changes.
   * @returns Unsubscribe function
   */
  onUnlockChange(listener: () => void): () => void {
    this.unlockListeners.add(listener)
    return () => this.unlockListeners.delete(listener)
  }

  private notifyUnlockChange(): void {
    this.unlockListeners.forEach(l => l())
  }

  /**
   * Initialize the KeyManager.
   * Must be called before any other operations.
   * Automatically restores UMK from IndexedDB if available.
   */
  async initialize(): Promise<void> {
    if (this._isInitialized) return
    await this.keyStore.initialize()
    this._isInitialized = true

    // Try to auto-restore UMK from IndexedDB
    await this.tryAutoUnlock()
  }

  /**
   * Try to automatically unlock using stored UMK.
   * This is called during initialization.
   */
  private async tryAutoUnlock(): Promise<void> {
    try {
      const storedUmk = await this.keyStore.loadSessionUmk()
      if (!storedUmk) return

      const storedKeys = await this.keyStore.loadKeys()
      if (!storedKeys) {
        // No keys stored, clear the orphaned UMK
        await this.keyStore.clearSessionUmk()
        return
      }

      // Try to decrypt user keys with the stored UMK
      const userKeys = await decryptUserKeys(storedKeys, storedUmk)
      this.umk = storedUmk
      this.userKeys = userKeys
      this.notifyUnlockChange()
    } catch {
      // Failed to auto-unlock, clear invalid UMK
      await this.keyStore.clearSessionUmk()
    }
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
    const kdfParams = buildKdfParams(umkResult.kdf, umkResult.kdfParams)

    const storedKeys: StoredKeys = {
      ...encryptedKeys,
      salt: umkResult.salt,
      kdf: umkResult.kdf,
      kdfParams,
      createdAt: Date.now(),
    }

    await this.keyStore.saveKeys(storedKeys)

    // Persist UMK for session continuity (auto-unlock on page reload)
    await this.keyStore.saveSessionUmk(umkResult.umk)

    // Keep UMK and keys in memory
    this.umk = umkResult.umk
    this.userKeys = userKeys

    // Get public keys for server registration
    const publicKeys = await getPublicKeysBase64(userKeys)

    // Create encrypted keys bundle for server storage
    const encryptedKeysBundle: EncryptedKeysBundle = {
      encryptedEcdhPrivateKey: await toBase64(encryptedKeys.encryptedEcdhPrivateKey),
      encryptedEcdhPrivateKeyNonce: await toBase64(encryptedKeys.encryptedEcdhPrivateKeyNonce),
      encryptedSigningPrivateKey: await toBase64(encryptedKeys.encryptedSigningPrivateKey),
      encryptedSigningPrivateKeyNonce: await toBase64(encryptedKeys.encryptedSigningPrivateKeyNonce),
      ecdhPublicKey: publicKeys.ecdhPublicKey,
      signingPublicKey: publicKeys.signingPublicKey,
    }

    return {
      recoveryKey: umkResult.recoveryKey,
      publicKeys,
      salt: umkResult.salt,
      kdf: umkResult.kdf,
      kdfParams: umkResult.kdfParams,
      encryptedKeysBundle,
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

    const umk = await deriveUmkFromPassphrase(
      passphrase,
      storedKeys.salt,
      storedKeys.kdf,
      storedKeys.kdfParams
    )

    await this.performUnlock(umk, storedKeys, 'Incorrect passphrase')
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

    const umk = restoreUmkFromRecoveryKey(recoveryKey)
    await this.performUnlock(umk, storedKeys, 'Incorrect recovery key')
  }

  /**
   * Lock the session - clears all keys from memory.
   */
  lock(): void {
    const wasUnlocked = this.isUnlocked
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

    if (wasUnlocked) {
      this.notifyUnlockChange()
    }
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
  // Server Restore
  // ============================================

  /**
   * Restore keys from server backup.
   * Used when logging in on a new device.
   *
   * @param passphrase - User's passphrase
   * @param serverBackup - Backup data from server
   */
  async restoreFromServer(
    passphrase: string,
    serverBackup: {
      encryptedKeysBundle: EncryptedKeysBundle
      salt: string
      kdfType: 'argon2id' | 'pbkdf2'
      kdfParams: { memory?: number | null; iterations?: number | null; parallelism?: number | null }
    }
  ): Promise<void> {
    await this.ensureInitialized()

    const salt = await fromBase64(serverBackup.salt)
    const kdfParams = buildKdfParams(serverBackup.kdfType, serverBackup.kdfParams)

    const umk = await deriveUmkFromPassphrase(
      passphrase,
      salt,
      serverBackup.kdfType,
      kdfParams
    )

    await this.performRestore(umk, serverBackup, 'Incorrect passphrase')
  }

  /**
   * Restore keys from server using recovery key.
   *
   * @param recoveryKey - BIP39 mnemonic (24 words)
   * @param serverBackup - Backup data from server
   */
  async restoreFromServerWithRecoveryKey(
    recoveryKey: string,
    serverBackup: {
      encryptedKeysBundle: EncryptedKeysBundle
      salt: string
      kdfType: 'argon2id' | 'pbkdf2'
      kdfParams: { memory?: number | null; iterations?: number | null; parallelism?: number | null }
    }
  ): Promise<void> {
    await this.ensureInitialized()

    const umk = restoreUmkFromRecoveryKey(recoveryKey)
    await this.performRestore(umk, serverBackup, 'Incorrect recovery key')
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

  /**
   * Create and store a new workspace KEK.
   * Used when creating a new workspace.
   *
   * @param workspaceId - Workspace ID
   * @returns The raw KEK (for immediate use)
   */
  async createAndStoreWorkspaceKek(workspaceId: string): Promise<Uint8Array> {
    this.ensureUnlocked()

    // 1. Generate new KEK
    const kek = await generateWorkspaceKek()

    // 2. Encrypt for self
    const userPublicKey = this.userKeys!.ecdh.publicKey
    const { encryptedKek, ephemeralPublicKey, nonce } = await encryptKekForRecipient(
      kek,
      userPublicKey
    )

    // 3. Encode and store via API
    const encryptedKekBase64 = await encodeKekForApi(encryptedKek, ephemeralPublicKey, nonce)
    await storeWorkspaceKey({
      id: workspaceId,
      requestBody: { encryptedKek: encryptedKekBase64, keyVersion: 1 },
    })

    // 4. Cache
    getKekCache().setKek(workspaceId, kek)

    return kek
  }

  /**
   * Get or create workspace KEK.
   * If no KEK exists for the workspace, creates one automatically.
   *
   * @param workspaceId - Workspace ID
   * @returns The raw KEK
   */
  async getOrCreateWorkspaceKek(workspaceId: string): Promise<Uint8Array> {
    this.ensureUnlocked()

    // Check cache first
    const cachedKek = getKekCache().getKek(workspaceId)
    if (cachedKek) {
      return cachedKek
    }

    // Try to fetch from server
    try {
      const response = await getMyWorkspaceKey({ id: workspaceId })
      return await this.decryptKek(response.encryptedKek)
    } catch (error: unknown) {
      // If 404, create new KEK
      if (error && typeof error === 'object' && 'status' in error && error.status === 404) {
        console.log(`[KeyManager] No KEK found for workspace ${workspaceId}, creating new one`)
        return this.createAndStoreWorkspaceKek(workspaceId)
      }
      throw error
    }
  }

  /**
   * Encrypt workspace KEK for an invitation.
   * The KEK is encrypted using a key derived from the invitation token.
   *
   * @param workspaceId - Workspace ID
   * @param invitationToken - The invitation token
   * @returns Base64-encoded encrypted KEK for API storage
   */
  async encryptKekForInvitationToken(
    workspaceId: string,
    invitationToken: string
  ): Promise<string> {
    this.ensureUnlocked()

    // Get or create workspace KEK
    const kek = await this.getOrCreateWorkspaceKek(workspaceId)

    // Encrypt KEK with token-derived key
    const { ciphertext, nonce } = await encryptKekForInvitation(kek, invitationToken)

    // Encode for API
    return encodeInvitationKekForApi(ciphertext, nonce)
  }

  /**
   * Decrypt KEK from invitation and store for self.
   * Called when accepting a workspace invitation.
   *
   * @param workspaceId - Workspace ID
   * @param invitationToken - The invitation token
   * @param encryptedKekBase64 - Base64-encoded encrypted KEK from invitation
   * @param keyVersion - Key version
   */
  async acceptInvitationAndStoreKek(
    workspaceId: string,
    invitationToken: string,
    encryptedKekBase64: string,
    keyVersion: number
  ): Promise<void> {
    this.ensureUnlocked()

    // 1. Decode invitation-encrypted KEK
    const { nonce, ciphertext } = await decodeInvitationKekFromApi(encryptedKekBase64)

    // 2. Decrypt KEK using invitation token
    const kek = await decryptKekFromInvitation(ciphertext, nonce, invitationToken)

    // 3. Re-encrypt for self
    const userPublicKey = this.userKeys!.ecdh.publicKey
    const encrypted = await encryptKekForRecipient(kek, userPublicKey)
    const encryptedKekForSelf = await encodeKekForApi(
      encrypted.encryptedKek,
      encrypted.ephemeralPublicKey,
      encrypted.nonce
    )

    // 4. Store via API
    await storeWorkspaceKey({
      id: workspaceId,
      requestBody: { encryptedKek: encryptedKekForSelf, keyVersion },
    })

    // 5. Cache
    getKekCache().setKek(workspaceId, kek)
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
    const kdfParams = buildKdfParams(umkResult.kdf, umkResult.kdfParams)

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

  /**
   * Common unlock logic shared by unlockWithPassphrase and unlockWithRecoveryKey.
   */
  private async performUnlock(
    umk: Uint8Array,
    storedKeys: StoredKeys,
    errorMessage: string
  ): Promise<void> {
    try {
      const userKeys = await decryptUserKeys(storedKeys, umk)
      this.umk = umk
      this.userKeys = userKeys
      await this.keyStore.saveSessionUmk(umk)
      this.notifyUnlockChange()
    } catch {
      umk.fill(0)
      throw new Error(errorMessage)
    }
  }

  /**
   * Common restore logic shared by restoreFromServer and restoreFromServerWithRecoveryKey.
   */
  private async performRestore(
    umk: Uint8Array,
    serverBackup: {
      encryptedKeysBundle: EncryptedKeysBundle
      salt: string
      kdfType: 'argon2id' | 'pbkdf2'
      kdfParams: { memory?: number | null; iterations?: number | null; parallelism?: number | null }
    },
    errorMessage: string
  ): Promise<void> {
    const salt = await fromBase64(serverBackup.salt)
    const kdfParams = buildKdfParams(serverBackup.kdfType, serverBackup.kdfParams)

    const bundle = serverBackup.encryptedKeysBundle
    const storedKeys: StoredKeys = {
      encryptedEcdhPrivateKey: await fromBase64(bundle.encryptedEcdhPrivateKey),
      encryptedEcdhPrivateKeyNonce: await fromBase64(bundle.encryptedEcdhPrivateKeyNonce),
      encryptedSigningPrivateKey: await fromBase64(bundle.encryptedSigningPrivateKey),
      encryptedSigningPrivateKeyNonce: await fromBase64(bundle.encryptedSigningPrivateKeyNonce),
      ecdhPublicKey: await fromBase64(bundle.ecdhPublicKey),
      signingPublicKey: await fromBase64(bundle.signingPublicKey),
      salt,
      kdf: serverBackup.kdfType,
      kdfParams,
      createdAt: Date.now(),
    }

    try {
      const userKeys = await decryptUserKeys(storedKeys, umk)
      await this.keyStore.saveKeys(storedKeys)
      await this.keyStore.saveSessionUmk(umk)
      this.umk = umk
      this.userKeys = userKeys
      this.notifyUnlockChange()
    } catch {
      umk.fill(0)
      throw new Error(errorMessage)
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
