import { buildIdentityHybridEncryptionPrivateKeyMaterialAad, buildIdentitySigningAad } from "./aad";
import { encodeBase64Url } from "./encoding";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";

export interface RecoverableIdentitySecretRecord {
  id: string;
  user_id: string;
  identity_key_epoch: number;
  previous_record_hash: string;
  encrypted_identity_hybrid_signing_private_key_material: string;
  identity_hybrid_signing_private_key_material_nonce: string;
  encrypted_identity_hybrid_encryption_private_key_material: string;
  identity_hybrid_encryption_private_key_material_nonce: string;
  signing_key_id: string;
  encryption_key_id: string;
  signing_material_aad_hash: string;
  encryption_material_aad_hash: string;
  record_hash: string;
  is_current: boolean;
}

export function buildRecoverableIdentitySecretRecord(params: {
  id: string;
  userId: string;
  identityKeyEpoch: number;
  previousRecordHash: string;
  encryptedSigningPrivateMaterial: Uint8Array;
  signingPrivateMaterialNonce: Uint8Array;
  encryptedEncryptionPrivateMaterial: Uint8Array;
  encryptionPrivateMaterialNonce: Uint8Array;
  signingKeyId: string;
  encryptionKeyId: string;
  isCurrent: boolean;
}): RecoverableIdentitySecretRecord {
  const signingMaterialAadHash = blake3Base64Url(
    buildIdentitySigningAad(params.userId, params.signingKeyId, params.identityKeyEpoch),
  );
  const encryptionMaterialAadHash = blake3Base64Url(
    buildIdentityHybridEncryptionPrivateKeyMaterialAad(
      params.userId,
      params.encryptionKeyId,
      params.identityKeyEpoch,
    ),
  );
  const preimage = {
    protocol: "refmd.recoverable-identity-secret-record",
    version: 1,
    record_id: params.id,
    user_id: params.userId,
    identity_key_epoch: params.identityKeyEpoch,
    previous_record_hash: params.previousRecordHash,
    signing_key_id: params.signingKeyId,
    encryption_key_id: params.encryptionKeyId,
    signing_ciphertext_hash: blake3Base64Url(params.encryptedSigningPrivateMaterial),
    signing_nonce_hash: blake3Base64Url(params.signingPrivateMaterialNonce),
    signing_material_aad_hash: signingMaterialAadHash,
    encryption_ciphertext_hash: blake3Base64Url(params.encryptedEncryptionPrivateMaterial),
    encryption_nonce_hash: blake3Base64Url(params.encryptionPrivateMaterialNonce),
    encryption_material_aad_hash: encryptionMaterialAadHash,
  } satisfies StrictJsonValue;

  return {
    id: params.id,
    user_id: params.userId,
    identity_key_epoch: params.identityKeyEpoch,
    previous_record_hash: params.previousRecordHash,
    encrypted_identity_hybrid_signing_private_key_material: encodeBase64Url(
      params.encryptedSigningPrivateMaterial,
    ),
    identity_hybrid_signing_private_key_material_nonce: encodeBase64Url(
      params.signingPrivateMaterialNonce,
    ),
    encrypted_identity_hybrid_encryption_private_key_material: encodeBase64Url(
      params.encryptedEncryptionPrivateMaterial,
    ),
    identity_hybrid_encryption_private_key_material_nonce: encodeBase64Url(
      params.encryptionPrivateMaterialNonce,
    ),
    signing_key_id: params.signingKeyId,
    encryption_key_id: params.encryptionKeyId,
    signing_material_aad_hash: signingMaterialAadHash,
    encryption_material_aad_hash: encryptionMaterialAadHash,
    record_hash: blake3Base64Url(canonicalizeStrictBytes(preimage)),
    is_current: params.isCurrent,
  };
}
