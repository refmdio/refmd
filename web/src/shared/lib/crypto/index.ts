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
export { generateUmk, wrapUmk, unwrapUmk, encryptUmkForDevice, decryptUmkFromDevice } from './umk'

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
  isValidX25519PublicKey,
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

// AAD constants and helpers
export {
  SIGNATURE_PROTOCOL,
  AAD_PURPOSE,
  buildAad,
  buildUmkWrapAad,
  buildRecoveryUmkWrapAad,
  buildIdentityEcdhAad,
  buildIdentitySigningAad,
  buildDeviceUmkDistributionAad,
  buildDekWrapAad,
  buildDocumentContentAad,
  type AadPurpose,
  type AadCommonHeader,
} from './aad'

// Document encryption functions
export {
  generateDek,
  wrapDek,
  unwrapDek,
  encryptContent,
  decryptContent,
} from './document'

// DSK (Device Storage Key) functions
export {
  generateDsk,
  storeDsk,
  loadDsk,
  wrapAndStoreUmk,
  loadAndUnwrapUmk,
  clearSessionCache,
  clearDskData,
  hasCachedSession,
  storeDeviceId,
  loadDeviceId,
  wrapAndStoreDeviceKeys,
  loadAndUnwrapDeviceKeys,
  hasDeviceKeys,
  hasDeviceKeysForUser,
  // Session storage (for rememberMe=false)
  storeSessionUmk,
  loadSessionUmk,
  clearSessionUmk,
  hasSessionUmk,
} from './dsk'

// SAS (Short Authentication String) functions
export {
  SAS_EMOJIS,
  indicesToEmojis,
  generateSasIndices,
  generateSasEmojis,
  sasIndicesToEmojis,
} from './sas'

// Device key functions
export {
  generateDeviceKeyPair,
  generateClientNonce,
  signWithDeviceKey,
  verifyDeviceSignature,
  type DeviceKeyPair,
} from './device'

// PoP (Proof of Possession) functions
export {
  generatePopHeaders,
  POP_NONCE_HEADER,
  POP_SIGNATURE_HEADER,
  POP_DEVICE_ID_HEADER,
  type PopHeaders,
} from './pop'
