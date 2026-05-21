export const AAD_PROTOCOL = { protocol: "refmd", version: 1 } as const;
export const AAD_PURPOSE = {
  UMK_WRAP: "umk_wrap",
  RECOVERY_UMK_WRAP: "recovery_umk_wrap",
  IDENTITY_SIGNING: "identity_hybrid_signing_private_key_material",
  IDENTITY_HYBRID_ENCRYPTION_PRIVATE_KEY_MATERIAL:
    "identity_hybrid_encryption_private_key_material",
  DEK_WRAP: "dek_wrap",
  DOCUMENT_CONTENT: "document_content",
  DSK_UMK_CACHE: "dsk_umk_cache",
  DSK_DEVICE_ECDH_PRIVATE: "dsk_device_ecdh_private",
  DSK_DEVICE_MLKEM768_PRIVATE: "dsk_device_mlkem768_private",
  DSK_DEVICE_SIGNING_PRIVATE_KEY_MATERIAL: "dsk_device_hybrid_signing_private_key_material",
  DSK_SHARE_PARTICIPANT_SIGNING_PRIVATE_KEY_MATERIAL:
    "dsk_share_participant_hybrid_signing_private_key_material",
  DSK_SHARE_PARTICIPANT_AUTHORIZATION_SECRET: "dsk_share_participant_authorization_secret",
  DSK_SHARE_DEK_ENCRYPTION_KEY: "dsk_share_dek_encryption_key",
  DOCUMENT_TITLE: "document_title",
  OFFLINE_DOCUMENT_CACHE: "offline_document_cache",
  OFFLINE_PENDING_CHANGES: "offline_pending_changes",
  OFFLINE_DEK_CACHE: "offline_dek_cache",
  OFFLINE_KEK_CACHE: "offline_kek_cache",
  DSK_AUTH_BOOTSTRAP: "dsk_auth_bootstrap",
  DSK_STORE_VALUE: "dsk_store_value",
  DSK_UI_STATE: "dsk_ui_state",
  SHARE_DEK_WRAP: "share_dek_wrap",
  SHARE_MANAGE_ACCESS: "share_manage_access",
  GUEST_INVITE_REDEEM_MATERIAL: "guest_invite_redeem_material",
} as const;
function canonicalizeAadBytes(obj: Record<string, unknown>): Uint8Array {
  return canonicalizeStrictBytes(obj as StrictJsonValue);
}
interface AadHeader {
  purpose: string;
  [key: string]: unknown;
}
function buildAad(header: AadHeader): Uint8Array {
  return canonicalizeAadBytes({ ...AAD_PROTOCOL, ...header });
}
function buildHybridSigningPrivateMaterialAad(header: {
  purpose: string;
  owner_kind: "identity" | "device" | "share_participant_device";
  owner_id: string;
  signing_key_id: string;
  storage_scope: Record<string, unknown>;
}): Uint8Array {
  return canonicalizeAadBytes({
    protocol: "refmd.hybrid-signing-private-key-material-encryption",
    version: 1,
    purpose: header.purpose,
    owner_kind: header.owner_kind,
    owner_id: header.owner_id,
    signing_key_id: header.signing_key_id,
    suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
    suite_rank: 1000,
    storage_scope: header.storage_scope,
  });
}
export function buildUmkWrapAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.UMK_WRAP, user_id: userId });
}
export function buildRecoveryUmkWrapAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.RECOVERY_UMK_WRAP, user_id: userId });
}
export function buildIdentityHybridEncryptionPrivateKeyMaterialAad(
  userId: string,
  encryptionKeyId: string,
): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.IDENTITY_HYBRID_ENCRYPTION_PRIVATE_KEY_MATERIAL,
    owner_kind: "identity",
    owner_id: userId,
    encryption_key_id: encryptionKeyId,
    suite_id:
      "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
    suite_rank: 1000,
    storage_scope: {
      kind: "user_identity_key",
      user_id: userId,
    },
  });
}
export function buildIdentitySigningAad(userId: string, signingKeyId: string): Uint8Array {
  return buildHybridSigningPrivateMaterialAad({
    purpose: AAD_PURPOSE.IDENTITY_SIGNING,
    owner_kind: "identity",
    owner_id: userId,
    signing_key_id: signingKeyId,
    storage_scope: {
      kind: "user_identity_key",
      user_id: userId,
    },
  });
}
export function buildDskUmkCacheAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.DSK_UMK_CACHE, user_id: userId });
}
function buildDskHybridEncryptionPrivateMaterialAad(header: {
  purpose: string;
  owner_kind: "device" | "share_participant_device";
  owner_id: string;
  encryption_key_id: string;
  storage_scope: Record<string, unknown>;
}): Uint8Array {
  return buildAad({
    purpose: header.purpose,
    owner_kind: header.owner_kind,
    owner_id: header.owner_id,
    encryption_key_id: header.encryption_key_id,
    suite_id:
      "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
    suite_rank: 1000,
    storage_scope: header.storage_scope,
  });
}
export function buildDskDeviceEcdhAad(params: {
  userId: string;
  deviceId: string;
  encryptionKeyId: string;
}): Uint8Array {
  return buildDskHybridEncryptionPrivateMaterialAad({
    purpose: AAD_PURPOSE.DSK_DEVICE_ECDH_PRIVATE,
    owner_kind: "device",
    owner_id: params.deviceId,
    encryption_key_id: params.encryptionKeyId,
    storage_scope: {
      kind: "dsk_device_key_cache",
      user_id: params.userId,
      device_id: params.deviceId,
      cache_key: "wrapped-device-ecdh",
    },
  });
}
export function buildDskDeviceMlkem768Aad(params: {
  userId: string;
  deviceId: string;
  encryptionKeyId: string;
}): Uint8Array {
  return buildDskHybridEncryptionPrivateMaterialAad({
    purpose: AAD_PURPOSE.DSK_DEVICE_MLKEM768_PRIVATE,
    owner_kind: "device",
    owner_id: params.deviceId,
    encryption_key_id: params.encryptionKeyId,
    storage_scope: {
      kind: "dsk_device_key_cache",
      user_id: params.userId,
      device_id: params.deviceId,
      cache_key: "wrapped-device-mlkem768-material",
    },
  });
}
export function buildDskShareParticipantDeviceEcdhAad(params: {
  principalId: string;
  shareId: string;
  shareParticipantDeviceId: string;
  encryptionKeyId: string;
}): Uint8Array {
  return buildDskHybridEncryptionPrivateMaterialAad({
    purpose: AAD_PURPOSE.DSK_DEVICE_ECDH_PRIVATE,
    owner_kind: "share_participant_device",
    owner_id: params.shareParticipantDeviceId,
    encryption_key_id: params.encryptionKeyId,
    storage_scope: {
      kind: "dsk_share_participant_device_key_cache",
      principal_id: params.principalId,
      share_id: params.shareId,
      share_participant_device_id: params.shareParticipantDeviceId,
      cache_key: "wrapped-device-ecdh",
    },
  });
}
export function buildDskShareParticipantDeviceMlkem768Aad(params: {
  principalId: string;
  shareId: string;
  shareParticipantDeviceId: string;
  encryptionKeyId: string;
}): Uint8Array {
  return buildDskHybridEncryptionPrivateMaterialAad({
    purpose: AAD_PURPOSE.DSK_DEVICE_MLKEM768_PRIVATE,
    owner_kind: "share_participant_device",
    owner_id: params.shareParticipantDeviceId,
    encryption_key_id: params.encryptionKeyId,
    storage_scope: {
      kind: "dsk_share_participant_device_key_cache",
      principal_id: params.principalId,
      share_id: params.shareId,
      share_participant_device_id: params.shareParticipantDeviceId,
      cache_key: "wrapped-device-mlkem768-material",
    },
  });
}
export function buildDskDeviceSigningAad(
  userId: string,
  deviceId: string,
  signingKeyId: string,
): Uint8Array {
  return buildHybridSigningPrivateMaterialAad({
    purpose: AAD_PURPOSE.DSK_DEVICE_SIGNING_PRIVATE_KEY_MATERIAL,
    owner_kind: "device",
    owner_id: deviceId,
    signing_key_id: signingKeyId,
    storage_scope: {
      kind: "dsk_device_key_cache",
      user_id: userId,
      device_id: deviceId,
      cache_key: "wrapped-device-hybrid-signing",
    },
  });
}
export function buildDskShareParticipantSigningAad(
  shareId: string,
  shareParticipantDeviceId: string,
  signingKeyId: string,
): Uint8Array {
  return buildHybridSigningPrivateMaterialAad({
    purpose: AAD_PURPOSE.DSK_SHARE_PARTICIPANT_SIGNING_PRIVATE_KEY_MATERIAL,
    owner_kind: "share_participant_device",
    owner_id: shareParticipantDeviceId,
    signing_key_id: signingKeyId,
    storage_scope: {
      kind: "dsk_share_participant_key_cache",
      share_id: shareId,
      share_participant_device_id: shareParticipantDeviceId,
      cache_key: "wrapped-share-participant-hybrid-signing",
    },
  });
}
export function buildDskShareParticipantAuthorizationSecretAad(
  principalId: string,
  deviceId: string,
  shareSlug: string,
): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.DSK_SHARE_PARTICIPANT_AUTHORIZATION_SECRET,
    principal_id: principalId,
    device_id: deviceId,
    share_slug: shareSlug,
  });
}
export function buildDskShareDekEncryptionKeyAad(
  principalId: string,
  deviceId: string,
  shareSlug: string,
): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.DSK_SHARE_DEK_ENCRYPTION_KEY,
    principal_id: principalId,
    device_id: deviceId,
    share_slug: shareSlug,
  });
}
export function buildDekWrapAad(documentId: string, workspaceId: string): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.DEK_WRAP,
    document_id: documentId,
    workspace_id: workspaceId,
  });
}
export function buildDocumentContentAad(documentId: string, keyVersion: number): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.DOCUMENT_CONTENT,
    document_id: documentId,
    key_version: keyVersion,
  });
}
export function buildDocumentTitleAad(documentId: string, keyVersion: number): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.DOCUMENT_TITLE,
    document_id: documentId,
    key_version: keyVersion,
  });
}

export function buildShareDekWrapAad(shareId: string, documentId: string): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.SHARE_DEK_WRAP,
    share_id: shareId,
    document_id: documentId,
  });
}
export function buildShareManageAccessAad(documentId: string, shareId: string): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.SHARE_MANAGE_ACCESS,
    document_id: documentId,
    share_id: shareId,
  });
}
export function buildGuestInviteRedeemMaterialAad(tokenHash: string): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.GUEST_INVITE_REDEEM_MATERIAL,
    token_hash: tokenHash,
  });
}
export function buildOfflineDocumentCacheAad(documentId: string, keyVersion: number): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.OFFLINE_DOCUMENT_CACHE,
    document_id: documentId,
    key_version: keyVersion,
  });
}
export function buildOfflinePendingChangesAad(documentId: string, keyVersion: number): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.OFFLINE_PENDING_CHANGES,
    document_id: documentId,
    key_version: keyVersion,
  });
}
export function buildOfflineDekCacheAad(documentId: string, keyVersion: number): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.OFFLINE_DEK_CACHE,
    document_id: documentId,
    key_version: keyVersion,
  });
}
export function buildOfflineKekCacheAad(workspaceId: string, keyVersion: number): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.OFFLINE_KEK_CACHE,
    workspace_id: workspaceId,
    key_version: keyVersion,
  });
}
export function buildDskAuthBootstrapAad(): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.DSK_AUTH_BOOTSTRAP });
}
export function buildDskStoreValueAad(key: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.DSK_STORE_VALUE, key });
}
export function buildDskUiStateAad(aadRecord: Record<string, unknown>): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.DSK_UI_STATE, ...aadRecord });
}
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
