export { base64UrlEncode, base64UrlDecode, randomBytes, constantTimeEqual } from "./encoding";
export {
  canonicalizeBytes,
  AAD_PURPOSE,
  buildDeviceUmkDistributionAad,
  buildDekWrapAad,
  buildDocumentContentAad,
  buildDocumentTitleAad,
} from "./aad";
export { generateDek, wrapDek, unwrapDek, encryptTitle, decryptTitle } from "./dek";
export { SIGNATURE_PROTOCOL, SIGNATURE_ACTION, buildSignatureMessage } from "./signature";
export { deriveAuthKeys } from "./kdf";
export type { KdfParams, DerivedKeys } from "./kdf";
export {
  generateIdentityKeyPair,
  encryptIdentityKeys,
  decryptIdentityPrivateKeys,
  sign,
  verify,
  ecdhSharedSecret,
} from "./identity";
export type { IdentityKeyPair, EncryptedIdentityKeys } from "./identity";
export { generateUmk, wrapUmk, unwrapUmk } from "./umk";
export {
  generateRecoveryKey,
  deriveRukFromMnemonic,
  wrapUmkWithRuk,
  unwrapUmkWithRuk,
  isValidMnemonic,
} from "./recovery";
export type { RecoveryKeyData } from "./recovery";
export { ecdhEncrypt, ecdhDecrypt } from "./ecdh-cipher";
export {
  generateKek,
  encryptKekForDevice,
  decryptKekFromDeviceEnvelope,
  encryptKekForMember,
  decryptKekFromMemberEnvelope,
  unwrapKekFromBackup,
  wrapKekWithUmk,
  encryptKekForInvitation,
  decryptKekFromInvitation,
} from "./kek";
export {
  generateDeviceKeyPair,
  generateClientNonce,
  signDeviceApproval,
  signDeviceRegistration,
  verifyDeviceIdentitySignature,
} from "./device";
export type { DeviceKeyPair } from "./device";
export {
  generateDsk,
  loadDsk,
  storeWrappedUmk,
  loadWrappedUmk,
  storeWrappedDeviceKeys,
  loadWrappedDeviceKeys,
  clearWrappedKeys,
} from "./dsk";
export {
  storePdkWrappedUmk,
  loadPdkWrappedUmk,
  storePdkWrappedDeviceKeys,
  loadPdkWrappedDeviceKeys,
  clearPdkWrappedKeys,
} from "./pdk";
export { isValidX25519PublicKey, isValidEd25519PublicKey } from "./key-validation";
export { computeSas } from "./sas";
export type { SasResult } from "./sas";
export { calculateFingerprint, formatFingerprint } from "./fingerprint";
export {
  verifyTofu,
  trustDevice,
  updateDeviceLastSeen,
  handleTofuResult,
  verifyAllDeviceTofu,
  TofuHardFailError,
} from "./tofu";
export type { TofuStatus, TofuVerifyResult } from "./tofu";
export { encryptTrustState, decryptTrustState } from "./trust-transfer";
export type {
  TrustStateSnapshot,
  EncryptedTrustState,
  TrustTransferAadParams,
} from "./trust-transfer";
