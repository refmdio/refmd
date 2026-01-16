/**
 * E2EE Crypto Module
 *
 * Exports all cryptographic primitives for E2EE implementation.
 */

// Sodium initialization
export { getSodium, isSodiumReady, type Sodium } from './sodium'

// XChaCha20-Poly1305 encryption
export {
  encrypt,
  decrypt,
  encryptDek,
  decryptDek,
  encryptString,
  decryptString,
  generateKey,
  generateNonce,
  NONCE_SIZE,
  KEY_SIZE,
  TAG_SIZE,
  type EncryptResult,
} from './xchacha20'

// Ed25519 signatures
export {
  sign,
  verify,
  signToBase64,
  verifyFromBase64,
  generateKeyPair as generateSigningKeyPair,
  buildSigningMessage,
  SIGNATURE_DOMAINS,
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  SIGNATURE_SIZE,
  type Ed25519KeyPair,
  type SigningMessage,
  type SignatureDomain,
} from './ed25519'

// JSON canonicalization
export {
  canonicalize,
  canonicalizeAndToBase64,
  fromBase64Json,
  toBase64,
  fromBase64,
} from './canonicalize'

// HKDF key derivation
export {
  deriveKey as hkdfDeriveKey,
  generateMasterKey as hkdfGenerateMasterKey,
  HKDF_CONTEXTS,
  SUBKEY_IDS,
  MASTER_KEY_SIZE,
  MIN_KEY_SIZE,
  MAX_KEY_SIZE,
} from './hkdf'

// Argon2id KDF
export {
  deriveKey as argon2DeriveKey,
  deriveKeyWithNewSalt as argon2DeriveKeyWithNewSalt,
  generateSalt as argon2GenerateSalt,
  isArgon2Supported,
  DEFAULT_ARGON2_PARAMS,
  SALT_SIZE as ARGON2_SALT_SIZE,
  type Argon2Params,
} from './argon2'

// PBKDF2 fallback
export {
  deriveKey as pbkdf2DeriveKey,
  deriveKeyWithNewSalt as pbkdf2DeriveKeyWithNewSalt,
  generateSalt as pbkdf2GenerateSalt,
  DEFAULT_ITERATIONS as PBKDF2_DEFAULT_ITERATIONS,
  SALT_SIZE as PBKDF2_SALT_SIZE,
} from './pbkdf2'

// ECDH key exchange
export {
  generateKeyPair as generateEcdhKeyPair,
  getPublicKey as getEcdhPublicKey,
  computeSharedSecret,
  deriveSharedKey,
  encryptKeyForRecipient,
  decryptKeyFromSender,
  isValidPublicKey as isValidEcdhPublicKey,
  PRIVATE_KEY_SIZE as ECDH_PRIVATE_KEY_SIZE,
  PUBLIC_KEY_SIZE_UNCOMPRESSED as ECDH_PUBLIC_KEY_SIZE,
  SHARED_SECRET_SIZE,
  type EcdhKeyPair,
} from './ecdh'

// BIP39 recovery keys
export {
  generateRecoveryKey,
  validateRecoveryKey,
  recoveryKeyToUmk,
  umkToRecoveryKey,
  getWordsAtIndices,
  verifyWords,
  generateVerificationIndices,
  getWordList,
  WORD_COUNT,
  ENTROPY_BITS,
  ENTROPY_BYTES,
} from './bip39'
