/**
 * Deterministic encryption for tags using HMAC-SHA256
 *
 * Since E2EE prevents server-side tag extraction, we need deterministic
 * encryption so the server can group documents by encrypted tags.
 *
 * Properties:
 * - Same plaintext + key = same ciphertext (deterministic)
 * - Different plaintexts = different ciphertexts (collision-resistant)
 * - One-way function (cannot derive plaintext from ciphertext without known plaintexts)
 */

import { getSodium } from '@/shared/lib/crypto'

/** Domain separation prefix for tag encryption */
const TAG_DOMAIN_PREFIX = 'refmd:tag:'

/** HMAC key size (same as KEK size) */
export const HMAC_KEY_SIZE = 32

/**
 * Encrypt a tag deterministically using HMAC-SHA256.
 *
 * @param tag - Plaintext tag (will be lowercased)
 * @param kek - Workspace KEK (32 bytes)
 * @returns Base64-encoded HMAC output
 *
 * @example
 * const encrypted = await encryptTagDeterministic("hello", kek)
 * // Same tag + KEK always produces same output
 */
export async function encryptTagDeterministic(
  tag: string,
  kek: Uint8Array
): Promise<string> {
  if (!tag || typeof tag !== 'string') {
    throw new Error('Tag must be a non-empty string')
  }
  if (kek.length !== HMAC_KEY_SIZE) {
    throw new Error(`Invalid KEK length: expected ${HMAC_KEY_SIZE}, got ${kek.length}`)
  }

  const sodium = await getSodium()

  // Normalize tag to lowercase for consistent encryption
  const normalizedTag = tag.toLowerCase().trim()
  if (normalizedTag.length === 0) {
    throw new Error('Tag must not be empty after normalization')
  }

  // Domain-separated message: "refmd:tag:<tag>"
  const message = new TextEncoder().encode(TAG_DOMAIN_PREFIX + normalizedTag)

  // HMAC-SHA256 using libsodium's crypto_auth (uses HMAC-SHA512-256 but similar security)
  // Note: crypto_auth produces 32-byte output which is sufficient for our needs
  const mac = sodium.crypto_auth(message, kek)

  return sodium.to_base64(mac, sodium.base64_variants.ORIGINAL)
}

/**
 * Encrypt multiple tags deterministically.
 *
 * @param tags - Array of plaintext tags
 * @param kek - Workspace KEK (32 bytes)
 * @returns Array of Base64-encoded encrypted tags (same order as input)
 */
export async function encryptTags(
  tags: string[],
  kek: Uint8Array
): Promise<string[]> {
  return Promise.all(tags.map((tag) => encryptTagDeterministic(tag, kek)))
}

/**
 * Build a lookup table for decrypting tags.
 *
 * Since HMAC is a one-way function, we cannot directly decrypt.
 * Instead, we pre-compute encryptions of known tags and use them
 * to reverse-lookup plaintexts.
 *
 * @param knownTags - Array of known plaintext tags
 * @param kek - Workspace KEK (32 bytes)
 * @returns Map from encrypted tag (Base64) to plaintext tag
 *
 * @example
 * const table = await buildTagLookupTable(["hello", "world"], kek)
 * const plaintext = table.get(encryptedTag) // "hello" or "world" or undefined
 */
export async function buildTagLookupTable(
  knownTags: string[],
  kek: Uint8Array
): Promise<Map<string, string>> {
  const table = new Map<string, string>()

  // Deduplicate and normalize
  const uniqueTags = [...new Set(knownTags.map((t) => t.toLowerCase().trim()))].filter(
    (t) => t.length > 0
  )

  for (const tag of uniqueTags) {
    const encrypted = await encryptTagDeterministic(tag, kek)
    table.set(encrypted, tag)
  }

  return table
}

/**
 * Decrypt a tag using a pre-built lookup table.
 *
 * @param encryptedTag - Base64-encoded encrypted tag
 * @param lookupTable - Map from encrypted to plaintext (from buildTagLookupTable)
 * @returns Plaintext tag or null if not found in lookup table
 */
export function decryptTag(
  encryptedTag: string,
  lookupTable: Map<string, string>
): string | null {
  return lookupTable.get(encryptedTag) ?? null
}

/**
 * Decrypt multiple tags using a lookup table.
 *
 * @param encryptedTags - Array of Base64-encoded encrypted tags
 * @param lookupTable - Lookup table
 * @returns Array of results (plaintext or null for each)
 */
export function decryptTags(
  encryptedTags: string[],
  lookupTable: Map<string, string>
): (string | null)[] {
  return encryptedTags.map((et) => decryptTag(et, lookupTable))
}

/**
 * Tag lookup table manager with caching.
 *
 * Maintains a set of known tags and rebuilds the lookup table
 * when new tags are added.
 */
export class TagLookupManager {
  private knownTags: Set<string> = new Set()
  private lookupTable: Map<string, string> = new Map()
  private kek: Uint8Array | null = null
  private dirty = true

  /**
   * Set the workspace KEK for encryption/decryption.
   * Invalidates the lookup table.
   */
  setKek(kek: Uint8Array): void {
    this.kek = kek
    this.dirty = true
  }

  /**
   * Add known tags to the manager.
   * Call rebuildLookupTable() after adding to update the lookup.
   */
  addKnownTags(tags: string[]): void {
    const sizeBefore = this.knownTags.size
    for (const tag of tags) {
      const normalized = tag.toLowerCase().trim()
      if (normalized.length > 0) {
        this.knownTags.add(normalized)
      }
    }
    if (this.knownTags.size > sizeBefore) {
      this.dirty = true
    }
  }

  /**
   * Get all known tags.
   */
  getKnownTags(): string[] {
    return [...this.knownTags]
  }

  /**
   * Rebuild the lookup table if needed.
   * Call this before decrypting tags.
   */
  async rebuildLookupTable(): Promise<void> {
    if (!this.dirty || !this.kek) {
      return
    }

    this.lookupTable = await buildTagLookupTable([...this.knownTags], this.kek)
    this.dirty = false
  }

  /**
   * Decrypt a tag using the internal lookup table.
   * Automatically rebuilds if dirty.
   */
  async decrypt(encryptedTag: string): Promise<string | null> {
    await this.rebuildLookupTable()
    return decryptTag(encryptedTag, this.lookupTable)
  }

  /**
   * Encrypt a tag and add it to known tags.
   */
  async encrypt(tag: string): Promise<string> {
    if (!this.kek) {
      throw new Error('KEK not set')
    }
    this.addKnownTags([tag])
    return encryptTagDeterministic(tag, this.kek)
  }

  /**
   * Clear all state.
   */
  clear(): void {
    this.knownTags.clear()
    this.lookupTable.clear()
    this.kek = null
    this.dirty = true
  }
}

/** Global tag lookup manager instance */
let globalTagLookupManager: TagLookupManager | null = null

/**
 * Get the global tag lookup manager instance.
 */
export function getTagLookupManager(): TagLookupManager {
  if (!globalTagLookupManager) {
    globalTagLookupManager = new TagLookupManager()
  }
  return globalTagLookupManager
}

/**
 * Reset the global tag lookup manager (for testing).
 */
export function resetTagLookupManager(): void {
  globalTagLookupManager?.clear()
  globalTagLookupManager = null
}
