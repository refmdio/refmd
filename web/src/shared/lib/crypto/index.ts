/**
 * RefMD Crypto Module
 *
 * Implements E2EE cryptographic operations:
 * - Argon2id for password → master key derivation
 * - HKDF-SHA256 for key derivation (authKey, PUK)
 * - XChaCha20-Poly1305 for symmetric encryption
 * - X25519 for ECDH key exchange
 * - Ed25519 for signatures
 */

// KDF functions
export { deriveAuthKeys, deriveRegistrationKeys, type DerivedKeys, type KdfParams } from './kdf'

// UMK functions
export { generateUmk, wrapUmk, unwrapUmk } from './umk'

// Identity key functions
export {
  generateIdentityKeyPair,
  encryptIdentityKeys,
  decryptIdentityKeys,
  decryptIdentityPrivateKeys,
  deriveEcdhPublicKey,
  deriveSigningPublicKey,
  sign,
  verify,
  ecdhSharedSecret,
  type IdentityKeyPair,
  type EncryptedIdentityKeys,
  type EncryptedIdentityPrivateKeys,
} from './identity'

// Recovery key functions (BIP39)
export {
  generateRecoveryKey,
  deriveRukFromMnemonic,
  wrapUmkWithRuk,
  unwrapUmkWithRuk,
  isValidMnemonic,
  type RecoveryKeyData,
  type RecoveryWrappedUmk,
} from './recovery'

// Encoding utilities
export {
  base64UrlEncode,
  base64UrlDecode,
  base64Encode,
  base64Decode,
  bytesToHex,
  hexToBytes,
} from './encoding'
