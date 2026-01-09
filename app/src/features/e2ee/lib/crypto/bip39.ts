/**
 * BIP39 Recovery Key module
 *
 * Generates and validates 24-word mnemonic phrases for key recovery.
 * The mnemonic encodes 256 bits of entropy (the UMK).
 */

import * as bip39Lib from 'bip39'

/** Number of words in the recovery key */
export const WORD_COUNT = 24

/** Entropy size in bits (256 bits = 32 bytes = 24 words) */
export const ENTROPY_BITS = 256

/** Entropy size in bytes */
export const ENTROPY_BYTES = ENTROPY_BITS / 8

/**
 * Generate a new recovery key (24-word mnemonic).
 *
 * @returns 24-word mnemonic phrase
 */
export function generateRecoveryKey(): string {
  return bip39Lib.generateMnemonic(ENTROPY_BITS)
}

/**
 * Validate a recovery key (mnemonic phrase).
 *
 * @param mnemonic - The mnemonic phrase to validate
 * @returns true if valid, false otherwise
 */
export function validateRecoveryKey(mnemonic: string): boolean {
  return bip39Lib.validateMnemonic(mnemonic)
}

/**
 * Convert a recovery key (mnemonic) to User Master Key (UMK).
 *
 * @param mnemonic - 24-word mnemonic phrase
 * @returns 32-byte UMK
 * @throws Error if mnemonic is invalid
 */
export function recoveryKeyToUmk(mnemonic: string): Uint8Array {
  if (!validateRecoveryKey(mnemonic)) {
    throw new Error('Invalid recovery key (mnemonic)')
  }

  const entropy = bip39Lib.mnemonicToEntropy(mnemonic)
  // mnemonicToEntropy returns a hex string
  return hexToBytes(entropy)
}

/**
 * Convert a User Master Key (UMK) to recovery key (mnemonic).
 *
 * @param umk - 32-byte User Master Key
 * @returns 24-word mnemonic phrase
 * @throws Error if UMK length is invalid
 */
export function umkToRecoveryKey(umk: Uint8Array): string {
  if (umk.length !== ENTROPY_BYTES) {
    throw new Error(`Invalid UMK length: expected ${ENTROPY_BYTES}, got ${umk.length}`)
  }

  const entropy = bytesToHex(umk)
  return bip39Lib.entropyToMnemonic(entropy)
}

/**
 * Get specific words from a mnemonic for verification.
 * Used in the recovery key verification challenge.
 *
 * @param mnemonic - The mnemonic phrase
 * @param indices - 0-based indices of words to get
 * @returns Array of words at the specified indices
 */
export function getWordsAtIndices(mnemonic: string, indices: number[]): string[] {
  const words = mnemonic.split(' ')
  return indices.map(i => {
    if (i < 0 || i >= words.length) {
      throw new Error(`Invalid word index: ${i}`)
    }
    return words[i]
  })
}

/**
 * Verify specific words in a mnemonic.
 * Used for recovery key verification challenge.
 *
 * @param mnemonic - The full mnemonic phrase
 * @param indices - 0-based indices to verify
 * @param userWords - User-provided words to verify
 * @returns true if all words match, false otherwise
 */
export function verifyWords(
  mnemonic: string,
  indices: number[],
  userWords: string[]
): boolean {
  if (indices.length !== userWords.length) {
    return false
  }

  const correctWords = getWordsAtIndices(mnemonic, indices)
  return correctWords.every((word, i) =>
    word.toLowerCase() === userWords[i].toLowerCase().trim()
  )
}

/**
 * Generate random indices for verification challenge.
 * Selects n unique random indices from 0 to WORD_COUNT-1.
 *
 * @param count - Number of indices to generate (default: 2)
 * @returns Array of unique random indices (sorted)
 */
export function generateVerificationIndices(count = 2): number[] {
  const indices = new Set<number>()
  while (indices.size < count) {
    indices.add(Math.floor(Math.random() * WORD_COUNT))
  }
  return Array.from(indices).sort((a, b) => a - b)
}

/**
 * Get the word list used by BIP39.
 *
 * @returns Array of all BIP39 English words
 */
export function getWordList(): string[] {
  return bip39Lib.wordlists.english
}

// Helper functions
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}
