/**
 * RefMD Crypto Module — Shared layer barrel (intentional FSD design)
 *
 * Implements E2EE cryptographic operations:
 * - Argon2id for password → master key derivation
 * - HKDF-SHA256 for key derivation (authKey, PUK)
 * - XChaCha20-Poly1305 for symmetric encryption
 * - X25519 for ECDH key exchange
 * - Ed25519 for signatures
 *
 * Consumers SHOULD import from this barrel for consistency.
 * Submodule imports are reserved for internal (intra-crypto) use only.
 */

// KDF functions
export { deriveAuthKeys, HKDF_ZERO_SALT, type DerivedKeys, type KdfParams } from './kdf'

// UMK functions
export { generateUmk, wrapUmk, unwrapUmk, encryptUmkForDevice, decryptUmkFromDevice } from './umk'

// Identity key functions
export {
  generateIdentityKeyPair,
  encryptIdentityKeys,
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
  buildRecoverySessionMessage,
  type RecoveryKeyData,
  type RecoveryWrappedUmk,
} from './recovery'

// Encoding utilities
export {
  base64UrlEncode,
  base64UrlDecode,
  constantTimeEqual,
} from './encoding'

// Signature protocol (canonicalization, message building)
export {
  SIGNATURE_PROTOCOL,
  SIGNATURE_ACTION,
  canonicalizeBytes,
  buildSignatureMessage,
  type SignatureAction,
} from './signature'

// AAD constants and helpers
export {
  AAD_PURPOSE,
  buildAad,
  buildUmkWrapAad,
  buildRecoveryUmkWrapAad,
  buildIdentityEcdhAad,
  buildIdentitySigningAad,
  buildDeviceUmkDistributionAad,
  buildDeviceKekDistributionAad,
  buildUmkKekBackupAad,
  buildDekWrapAad,
  buildDocumentContentAad,
  buildInvitationKekWrapAad,
  type AadPurpose,
  type AadCommonHeader,
} from './aad'

// KEK (Key Encryption Key) functions
export {
  generateKek,
  encryptKekForDevice,
  decryptKekFromDevice,
  wrapKekWithUmk,
  unwrapKekWithUmk,
} from './kek'

// Document encryption functions
export {
  generateDek,
  wrapDek,
  unwrapDek,
  encryptContent,
  decryptContent,
  computeUpdateHash,
  signDocumentUpdate,
  verifyDocumentUpdate,
} from './document'

// DSK (Device Storage Key) functions
export {
  canPersistDsk,
  generateDsk,
  storeDsk,
  loadDsk,
  ensureDsk,
  wrapAndStoreUmk,
  loadAndUnwrapUmk,
  clearSessionCache,
  clearDskData,
  hasCachedSession,
  storeDeviceId,
  loadDeviceId,
  wrapAndStoreDeviceKeys,
  loadAndUnwrapDeviceKeys,
  // Session storage (for rememberMe=false)
  storeSessionUmk,
  loadSessionUmk,
  clearSessionUmk,
} from './dsk'

// PDK (Password Derived Key) functions - fallback when DSK unavailable
export {
  wrapAndStorePdkDeviceKeys,
  unwrapPdkDeviceKeys,
  hasPdkWrappedDeviceKeys,
  clearPdkWrappedDeviceKeys,
  updatePdkWraps,
  wrapAndStorePdkUmk,
  unwrapPdkUmk,
  clearPdkWrappedUmk,
  storePdkForDeviceRegistration,
  loadAndClearPdkForDeviceRegistration,
  clearPdkEphemeral,
} from './pdk'

// SAS (Short Authentication String) functions
export {
  SAS_EMOJIS,
  indicesToEmojis,
  generateSasIndices,
  generateSasEmojis,
} from './sas'

// Device key functions
export {
  generateDeviceKeyPair,
  generateClientNonce,
  signDeviceApproval,
  type DeviceKeyPair,
  type DeviceApprovalPayload,
} from './device'

// PoP (Proof of Possession) functions
export {
  getPopHeaders,
  fetchPopChallenge,
  signPopChallenge,
  POP_CHALLENGE_HEADER,
  POP_SIGNATURE_HEADER,
  POP_DEVICE_ID_HEADER,
  type PopHeaders,
  type PopChallengeResponse,
} from './pop'

// TOFU (Trust On First Use) functions
export {
  verifyTofu,
  trustDevice,
  updateDeviceLastSeen,
  handleTofuResult,
  type TofuStatus,
  type TofuVerifyResult,
} from './tofu'

// TOFU Policy (centralized decision logic)
export {
  evaluateTofu,
  evaluateTofuWithoutPersist,
  evaluateDeviceTofu,
  dispatchTofuDecision,
  verifyDeviceListTofu,
  toKeyChangeItem,
  assertTofuTrustedOrThrow,
  type TofuDecision,
  type TofuCategoryHandlers,
  type DeviceWithKeys,
  type DeviceListTofuResult,
  processDeviceListTofu,
  type CategorizedTofuResult,
} from './tofu-policy'

// Fingerprint functions
export {
  calculateFingerprint,
  formatFingerprint,
} from './fingerprint'

// Identity key helpers (API response decryption)
export {
  decryptIdentityKeysFromResponse,
  type EncryptedIdentityKeysResponse,
} from './identity-helpers'

// Trust Transfer functions
export {
  encryptTrustState,
  decryptTrustState,
  type TrustStateSnapshot,
  type EncryptedTrustState,
  type TrustTransferAadParams,
} from './trust-transfer'
