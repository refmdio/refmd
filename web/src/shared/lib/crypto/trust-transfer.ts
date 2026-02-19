/**
 * Trust State Transfer Module
 *
 * Provides secure transfer of TOFU trust state from an existing device
 * to a newly registered device.
 *
 * Security:
 * - ECDH + HKDF + XChaCha20-Poly1305 for encryption
 * - Ed25519 signature for authenticity
 * - Nonce binding for replay protection
 * - AAD for context binding
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { TofuEntry } from '../trust-store'
import { buildAad, AAD_PURPOSE } from './aad'
import { SIGNATURE_PROTOCOL, SIGNATURE_ACTION, buildSignatureMessage } from './signature'
import { ecdhSharedSecret, sign, verify } from './identity'
import { HKDF_ZERO_SALT } from './kdf'
import { base64UrlEncode, base64UrlDecode, constantTimeEqual } from './encoding'

/**
 * Trust state snapshot for transfer
 */
export interface TrustStateSnapshot {
  /** All TOFU entries to transfer */
  tofuEntries: TofuEntry[]
  /** Transfer nonce from server (32 bytes) */
  transferNonce: Uint8Array
}

/**
 * Encrypted trust state for transmission
 */
export interface EncryptedTrustState {
  /** XChaCha20-Poly1305 ciphertext */
  encryptedState: Uint8Array
  /** XChaCha20-Poly1305 nonce (24 bytes) */
  nonce: Uint8Array
  /** Ed25519 signature over ciphertext + transfer nonce */
  signature: Uint8Array
}

/**
 * AAD parameters for trust state transfer
 */
export interface TrustTransferAadParams {
  userId: string
  senderDeviceId: string
  targetDeviceId: string
}

/**
 * Serializable form of TofuEntry for JSON encoding
 */
interface SerializedTofuEntry {
  userId: string
  deviceId: string
  signingPublicKey: string // base64url
  ecdhPublicKey: string // base64url
  firstSeenAt: number
  lastSeenAt: number
}

/**
 * Serializable trust state snapshot
 */
interface SerializedSnapshot {
  entries: SerializedTofuEntry[]
  transferNonce: string // base64url
}

/**
 * Build AAD for trust state transfer
 */
function buildTrustTransferAad(params: TrustTransferAadParams): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.TRUST_STATE_TRANSFER,
    user_id: params.userId,
    sender_device_id: params.senderDeviceId,
    target_device_id: params.targetDeviceId,
  })
}

/**
 * Derive encryption key from ECDH shared secret using HKDF
 *
 * Uses 32-byte zero salt (safe for high-entropy IKM like ECDH shared secret)
 * The transfer nonce is bound via AAD, not the HKDF salt.
 */
function deriveTransferKey(sharedSecret: Uint8Array): Uint8Array {
  // HKDF with zero salt (safe for high-entropy IKM)
  // info: "trust_state_transfer" to differentiate from other key derivations
  const info = new TextEncoder().encode('trust_state_transfer')
  return hkdf(sha256, sharedSecret, HKDF_ZERO_SALT, info, 32)
}

/**
 * Serialize a TofuEntry for JSON encoding
 */
function serializeEntry(entry: TofuEntry): SerializedTofuEntry {
  return {
    userId: entry.userId,
    deviceId: entry.deviceId,
    signingPublicKey: base64UrlEncode(entry.signingPublicKey),
    ecdhPublicKey: base64UrlEncode(entry.ecdhPublicKey),
    firstSeenAt: entry.firstSeenAt,
    lastSeenAt: entry.lastSeenAt,
  }
}

/**
 * Deserialize a TofuEntry from JSON
 */
function deserializeEntry(serialized: SerializedTofuEntry): TofuEntry {
  return {
    userId: serialized.userId,
    deviceId: serialized.deviceId,
    signingPublicKey: base64UrlDecode(serialized.signingPublicKey),
    ecdhPublicKey: base64UrlDecode(serialized.ecdhPublicKey),
    firstSeenAt: serialized.firstSeenAt,
    lastSeenAt: serialized.lastSeenAt,
  }
}

/**
 * Build message for trust state transfer signature
 *
 * Uses signature protocol format with canonicalized JSON
 */
function buildTransferSignatureMessage(
  ciphertext: Uint8Array,
  transferNonce: Uint8Array
): Uint8Array {
  return buildSignatureMessage(SIGNATURE_ACTION.TRUST_STATE_TRANSFER, {
    ciphertext: base64UrlEncode(ciphertext),
    transfer_nonce: base64UrlEncode(transferNonce),
  })
}

/**
 * Encrypt trust state for transfer to a new device
 *
 * @param snapshot Trust state snapshot to encrypt
 * @param senderEcdhPrivate Sender's X25519 private key
 * @param targetEcdhPublic Target device's X25519 public key
 * @param signingPrivate Sender's Ed25519 private key
 * @param aadParams AAD parameters for context binding
 * @returns Encrypted trust state
 */
export function encryptTrustState(
  snapshot: TrustStateSnapshot,
  senderEcdhPrivate: Uint8Array,
  targetEcdhPublic: Uint8Array,
  signingPrivate: Uint8Array,
  aadParams: TrustTransferAadParams
): EncryptedTrustState {
  // Serialize snapshot to JSON
  const serialized: SerializedSnapshot = {
    entries: snapshot.tofuEntries.map(serializeEntry),
    transferNonce: base64UrlEncode(snapshot.transferNonce),
  }
  const plaintext = new TextEncoder().encode(JSON.stringify(serialized))

  // Derive shared secret and encryption key
  const sharedSecret = ecdhSharedSecret(senderEcdhPrivate, targetEcdhPublic)
  const encryptionKey = deriveTransferKey(sharedSecret)

  // Generate nonce and build AAD
  const nonce = randomBytes(24)
  const aad = buildTrustTransferAad(aadParams)

  // Encrypt with XChaCha20-Poly1305
  const cipher = xchacha20poly1305(encryptionKey, nonce, aad)
  const encryptedState = cipher.encrypt(plaintext)

  // Sign using signature protocol format
  const signatureMessage = buildTransferSignatureMessage(encryptedState, snapshot.transferNonce)
  const signature = sign(signatureMessage, signingPrivate)

  return {
    encryptedState,
    nonce,
    signature,
  }
}

/**
 * Decrypt trust state received from another device
 *
 * @param encrypted Encrypted trust state
 * @param receiverEcdhPrivate Receiver's X25519 private key
 * @param senderEcdhPublic Sender's X25519 public key
 * @param senderSigningPublic Sender's Ed25519 public key
 * @param expectedNonce Expected transfer nonce from server
 * @param aadParams AAD parameters for context binding
 * @returns Decrypted trust state snapshot
 * @throws Error if verification or decryption fails
 */
export function decryptTrustState(
  encrypted: EncryptedTrustState,
  receiverEcdhPrivate: Uint8Array,
  senderEcdhPublic: Uint8Array,
  senderSigningPublic: Uint8Array,
  expectedNonce: Uint8Array,
  aadParams: TrustTransferAadParams
): TrustStateSnapshot {
  // Verify signature first (before decryption)
  const signatureMessage = buildTransferSignatureMessage(encrypted.encryptedState, expectedNonce)
  if (!verify(signatureMessage, encrypted.signature, senderSigningPublic)) {
    throw new Error('Trust state signature verification failed')
  }

  // Derive shared secret and encryption key
  const sharedSecret = ecdhSharedSecret(receiverEcdhPrivate, senderEcdhPublic)
  const encryptionKey = deriveTransferKey(sharedSecret)

  // Build AAD and decrypt
  const aad = buildTrustTransferAad(aadParams)
  const cipher = xchacha20poly1305(encryptionKey, encrypted.nonce, aad)
  const plaintext = cipher.decrypt(encrypted.encryptedState)

  // Parse JSON
  const json = new TextDecoder().decode(plaintext)
  const serialized: SerializedSnapshot = JSON.parse(json)

  // Verify nonce matches expected
  const receivedNonce = base64UrlDecode(serialized.transferNonce)
  if (!constantTimeEqual(receivedNonce, expectedNonce)) {
    throw new Error('Transfer nonce mismatch')
  }

  // Deserialize entries
  return {
    tofuEntries: serialized.entries.map(deserializeEntry),
    transferNonce: receivedNonce,
  }
}


