/**
 * KeyVaultService - Simplified API for encryption key operations
 *
 * This service provides a cleaner interface than KeyManager for common operations:
 * - Auto-initialization: No need to call initialize() manually
 * - Clear error handling: Throws SessionLockedError when locked
 * - Facade pattern: Delegates to KeyManager internally
 *
 * Usage:
 * ```typescript
 * const service = getKeyVaultService()
 * await service.ready() // Wait for initialization
 * service.ensureUnlocked() // Throws if locked
 * const kek = await service.getWorkspaceKek(workspaceId, fetchFn)
 * ```
 */

import { getKeyManager, KeyManager, SessionLockedError } from './keys'

let serviceInstance: KeyVaultService | null = null
let initPromise: Promise<void> | null = null

export class KeyVaultService {
  private readonly km: KeyManager

  constructor() {
    this.km = getKeyManager()
  }

  // ==========================================================================
  // Initialization
  // ==========================================================================

  /**
   * Wait for the service to be ready (initialized).
   * Call this before any operations if you need to ensure initialization.
   */
  async ready(): Promise<void> {
    if (!initPromise) {
      initPromise = this.km.initialize()
    }
    await initPromise
  }

  /**
   * Check if the service is initialized.
   */
  get isInitialized(): boolean {
    return this.km.isInitialized
  }

  // ==========================================================================
  // Session State
  // ==========================================================================

  /**
   * Check if the session is unlocked (keys are in memory).
   */
  get isUnlocked(): boolean {
    return this.km.isUnlocked
  }

  /**
   * Ensure the session is unlocked.
   * @throws SessionLockedError if the session is locked
   */
  ensureUnlocked(): void {
    if (!this.km.isUnlocked) {
      throw new SessionLockedError()
    }
  }

  /**
   * Check if local keys exist in storage.
   */
  async hasKeys(): Promise<boolean> {
    await this.ready()
    return this.km.hasKeys()
  }

  // ==========================================================================
  // Workspace KEK Operations
  // ==========================================================================

  /**
   * Get the workspace KEK (Key Encryption Key).
   * Auto-initializes if needed.
   *
   * @param workspaceId - Workspace ID
   * @param fetchFn - Function to fetch encrypted KEK from server
   * @returns KEK as Uint8Array
   * @throws SessionLockedError if session is locked
   */
  async getWorkspaceKek(
    workspaceId: string,
    fetchFn: () => Promise<string>
  ): Promise<Uint8Array> {
    await this.ready()
    this.ensureUnlocked()
    return this.km.getWorkspaceKek(workspaceId, fetchFn)
  }

  // ==========================================================================
  // Document DEK Operations
  // ==========================================================================

  /**
   * Get the document DEK (Document Encryption Key).
   * Auto-initializes if needed.
   *
   * @param documentId - Document ID
   * @param kek - Workspace KEK
   * @param fetchFn - Function to fetch encrypted DEK from server
   * @returns DEK as Uint8Array
   * @throws SessionLockedError if session is locked
   */
  async getDocumentDek(
    documentId: string,
    kek: Uint8Array,
    fetchFn: () => Promise<{ encryptedDek: string; nonce: string }>
  ): Promise<Uint8Array> {
    await this.ready()
    this.ensureUnlocked()
    return this.km.getDocumentDek(documentId, kek, fetchFn)
  }

  // ==========================================================================
  // Low-level Access (for advanced use cases)
  // ==========================================================================

  /**
   * Get the underlying KeyManager instance.
   * Use with caution - prefer the service methods when possible.
   */
  get keyManager(): KeyManager {
    return this.km
  }

  /**
   * Subscribe to unlock state changes.
   * @returns Unsubscribe function
   */
  onUnlockChange(callback: () => void): () => void {
    return this.km.onUnlockChange(callback)
  }
}

/**
 * Get the KeyVaultService singleton instance.
 * Automatically initializes on first access.
 */
export function getKeyVaultService(): KeyVaultService {
  if (!serviceInstance) {
    serviceInstance = new KeyVaultService()
    // Start initialization immediately but don't block
    serviceInstance.ready().catch((err) => {
      console.error('[KeyVaultService] Auto-initialization failed:', err)
    })
  }
  return serviceInstance
}

/**
 * Reset the service instance (for testing).
 */
export function resetKeyVaultService(): void {
  serviceInstance = null
  initPromise = null
}

// Re-export error type for convenience
export { SessionLockedError }
