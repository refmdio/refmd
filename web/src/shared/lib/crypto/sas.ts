/**
 * SAS (Short Authentication String) Generation
 *
 * ADR-008 compliant: BLAKE3 hash → 7 emojis (56 bits)
 * Used for device verification during multi-device registration.
 */

import { blake3 } from '@noble/hashes/blake3.js'

/**
 * 256 emoji set for SAS display
 * Each byte (0-255) maps to one emoji
 * Selected from Signal-style categories: animals, food, nature, sports, objects
 */
export const SAS_EMOJIS: readonly string[] = [
  // Animals (0-63)
  '🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼',
  '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🐔',
  '🐧', '🐦', '🐤', '🦆', '🦅', '🦉', '🦇', '🐺',
  '🐗', '🐴', '🦄', '🐝', '🐛', '🦋', '🐌', '🐞',
  '🐜', '🦟', '🦗', '🦂', '🐢', '🐍', '🦎', '🦖',
  '🦕', '🐙', '🦑', '🦐', '🦞', '🦀', '🐡', '🐠',
  '🐟', '🐬', '🐳', '🐋', '🦈', '🐊', '🐅', '🐆',
  '🦓', '🦍', '🦧', '🐘', '🦛', '🦏', '🐪', '🐫',

  // Food (64-127)
  '🍎', '🍐', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓',
  '🫐', '🍈', '🍒', '🍑', '🥭', '🍍', '🥥', '🥝',
  '🍅', '🍆', '🥑', '🥦', '🥬', '🥒', '🌶️', '🫑',
  '🌽', '🥕', '🧄', '🧅', '🥔', '🍠', '🥐', '🥯',
  '🍞', '🥖', '🥨', '🧀', '🥚', '🍳', '🧈', '🥞',
  '🧇', '🥓', '🥩', '🍗', '🍖', '🦴', '🌭', '🍔',
  '🍟', '🍕', '🫓', '🥪', '🥙', '🧆', '🌮', '🌯',
  '🫔', '🥗', '🥘', '🫕', '🍝', '🍜', '🍲', '🍛',

  // Nature & Plants (128-191)
  '🌲', '🌳', '🌴', '🌵', '🌾', '🌿', '☘️', '🍀',
  '🍁', '🍂', '🍃', '🍄', '🌸', '💐', '🌷', '🌹',
  '🥀', '🌺', '🌻', '🌼', '🌱', '🪴', '🪵', '🪨',
  '⛰️', '🏔️', '🌋', '🗻', '🏕️', '🏖️', '🏜️', '🏝️',
  '🌅', '🌄', '🌠', '🎇', '🎆', '🌈', '☀️', '🌤️',
  '⛅', '🌦️', '🌧️', '⛈️', '🌩️', '🌨️', '❄️', '☃️',
  '⛄', '🌬️', '💨', '🌪️', '🌫️', '🌊', '💧', '💦',
  '☔', '🌙', '⭐', '🌟', '✨', '💫', '🌍', '🌎',

  // Sports & Activities (192-223)
  '⚽', '🏀', '🏈', '⚾', '🥎', '🎾', '🏐', '🏉',
  '🥏', '🎱', '🪀', '🏓', '🏸', '🏒', '🏑', '🥍',
  '🏏', '🪃', '🥅', '⛳', '🪁', '🏹', '🎣', '🤿',
  '🥊', '🥋', '🎽', '🛹', '🛼', '🛷', '⛸️', '🥌',

  // Objects & Symbols (224-255)
  '🎸', '🪕', '🎹', '🎺', '🎻', '🪘', '🥁', '🪗',
  '🎤', '🎧', '📻', '🎬', '🎨', '🎭', '🎪', '🎰',
  '🚗', '🚕', '🚙', '🚌', '🚎', '🏎️', '🚓', '🚑',
  '🚒', '🚐', '🛻', '🚚', '🚛', '🚜', '✈️', '🚀',
] as const

/**
 * Convert SAS indices to emoji string
 * @param indices - Array of 7 byte values (0-255)
 * @returns String of 7 emojis
 */
export function indicesToEmojis(indices: readonly number[]): string {
  if (indices.length !== 7) {
    throw new Error('SAS indices must be exactly 7 bytes')
  }
  return indices.map((i) => SAS_EMOJIS[i]).join('')
}

/**
 * Generate SAS from device public keys and nonce
 *
 * ADR-008 algorithm:
 * 1. Concatenate: identity_signing_pk || device_signing_pk || device_ecdh_pk || client_nonce
 * 2. BLAKE3 hash
 * 3. Take first 7 bytes (56 bits)
 * 4. Convert each byte to emoji
 *
 * @param identitySigningPk - User's identity signing public key (32 bytes)
 * @param deviceSigningPk - New device's signing public key (32 bytes)
 * @param deviceEcdhPk - New device's ECDH public key (32 bytes)
 * @param clientNonce - Client-generated nonce (16 bytes)
 * @returns Array of 7 emoji indices (0-255)
 */
export function generateSasIndices(
  identitySigningPk: Uint8Array,
  deviceSigningPk: Uint8Array,
  deviceEcdhPk: Uint8Array,
  clientNonce: Uint8Array
): number[] {
  // Validate input lengths
  if (identitySigningPk.length !== 32) {
    throw new Error('Identity signing public key must be 32 bytes')
  }
  if (deviceSigningPk.length !== 32) {
    throw new Error('Device signing public key must be 32 bytes')
  }
  if (deviceEcdhPk.length !== 32) {
    throw new Error('Device ECDH public key must be 32 bytes')
  }
  if (clientNonce.length !== 16) {
    throw new Error('Client nonce must be 16 bytes')
  }

  // Concatenate all inputs
  const message = new Uint8Array(32 + 32 + 32 + 16)
  message.set(identitySigningPk, 0)
  message.set(deviceSigningPk, 32)
  message.set(deviceEcdhPk, 64)
  message.set(clientNonce, 96)

  // BLAKE3 hash
  const hash = blake3(message)

  // Take first 7 bytes as indices
  return Array.from(hash.slice(0, 7))
}

/**
 * Generate SAS emoji string from device public keys and nonce
 *
 * @param identitySigningPk - User's identity signing public key (32 bytes)
 * @param deviceSigningPk - New device's signing public key (32 bytes)
 * @param deviceEcdhPk - New device's ECDH public key (32 bytes)
 * @param clientNonce - Client-generated nonce (16 bytes)
 * @returns String of 7 emojis
 */
export function generateSasEmojis(
  identitySigningPk: Uint8Array,
  deviceSigningPk: Uint8Array,
  deviceEcdhPk: Uint8Array,
  clientNonce: Uint8Array
): string {
  const indices = generateSasIndices(identitySigningPk, deviceSigningPk, deviceEcdhPk, clientNonce)
  return indicesToEmojis(indices)
}

