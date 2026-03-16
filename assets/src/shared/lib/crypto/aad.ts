const AAD_PROTOCOL = { protocol: "refmd", version: 1 } as const;

export const AAD_PURPOSE = {
  UMK_WRAP: "umk_wrap",
  RECOVERY_UMK_WRAP: "recovery_umk_wrap",
  DEVICE_UMK_WRAP: "device_umk_wrap",
  IDENTITY_ECDH: "identity_ecdh",
  IDENTITY_SIGNING: "identity_signing",
  DEVICE_KEK_WRAP: "device_kek_wrap",
  UMK_KEK_BACKUP: "umk_kek_backup",
  DEK_WRAP: "dek_wrap",
  DOCUMENT_CONTENT: "document_content",
  TRUST_STATE_TRANSFER: "trust_state_transfer",
  MEMBER_ENVELOPE_KEK_WRAP: "member_envelope_kek_wrap",
  DSK_UMK_CACHE: "dsk_umk_cache",
  DSK_DEVICE_ECDH_PRIVATE: "dsk_device_ecdh_private",
  DSK_DEVICE_SIGNING_PRIVATE: "dsk_device_signing_private",
  INVITATION_KEK_WRAP: "invitation_kek_wrap",
  DOCUMENT_TITLE: "document_title",
  PDK_UMK_WRAP: "pdk_umk_wrap",
  PDK_DEVICE_ECDH_PRIVATE: "pdk_device_ecdh_private",
  PDK_DEVICE_SIGNING_PRIVATE: "pdk_device_signing_private",
} as const;

function canonicalize(obj: unknown): string {
  if (obj === null) return "null";
  if (typeof obj === "boolean" || typeof obj === "number") return JSON.stringify(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map((v) => canonicalize(v)).join(",") + "]";
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    const pairs = keys
      .filter((k) => (obj as Record<string, unknown>)[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + canonicalize((obj as Record<string, unknown>)[k]));
    return "{" + pairs.join(",") + "}";
  }
  throw new Error("Cannot canonicalize: " + typeof obj);
}

export function canonicalizeBytes(obj: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(canonicalize(obj));
}

interface AadHeader {
  purpose: string;
  [key: string]: unknown;
}

function buildAad(header: AadHeader): Uint8Array {
  return canonicalizeBytes({ ...AAD_PROTOCOL, ...header });
}

export function buildUmkWrapAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.UMK_WRAP, user_id: userId });
}

export function buildRecoveryUmkWrapAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.RECOVERY_UMK_WRAP, user_id: userId });
}

export function buildIdentityEcdhAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.IDENTITY_ECDH, user_id: userId });
}

export function buildIdentitySigningAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.IDENTITY_SIGNING, user_id: userId });
}

export function buildDeviceUmkDistributionAad(
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string,
): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.DEVICE_UMK_WRAP,
    user_id: userId,
    sender_device_id: senderDeviceId,
    target_device_id: targetDeviceId,
  });
}

export function buildDeviceKekDistributionAad(
  workspaceId: string,
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string,
  keyVersion: number,
): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.DEVICE_KEK_WRAP,
    workspace_id: workspaceId,
    user_id: userId,
    sender_device_id: senderDeviceId,
    target_device_id: targetDeviceId,
    key_version: keyVersion,
  });
}

export function buildUmkKekBackupAad(
  workspaceId: string,
  userId: string,
  keyVersion: number,
): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.UMK_KEK_BACKUP,
    workspace_id: workspaceId,
    user_id: userId,
    key_version: keyVersion,
  });
}

export function buildDskUmkCacheAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.DSK_UMK_CACHE, user_id: userId });
}

export function buildDskDeviceEcdhAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.DSK_DEVICE_ECDH_PRIVATE, user_id: userId });
}

export function buildDskDeviceSigningAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.DSK_DEVICE_SIGNING_PRIVATE, user_id: userId });
}

export function buildPdkUmkWrapAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.PDK_UMK_WRAP, user_id: userId });
}

export function buildPdkDeviceEcdhAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.PDK_DEVICE_ECDH_PRIVATE, user_id: userId });
}

export function buildPdkDeviceSigningAad(userId: string): Uint8Array {
  return buildAad({ purpose: AAD_PURPOSE.PDK_DEVICE_SIGNING_PRIVATE, user_id: userId });
}

export function buildInvitationKekWrapAad(
  workspaceId: string,
  invitationId: string,
  keyVersion: number,
): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.INVITATION_KEK_WRAP,
    workspace_id: workspaceId,
    invitation_id: invitationId,
    key_version: keyVersion,
  });
}

export function buildMemberEnvelopeKekAad(
  workspaceId: string,
  targetUserId: string,
  keyVersion: number,
  senderDeviceId: string,
): Uint8Array {
  return buildAad({
    purpose: AAD_PURPOSE.MEMBER_ENVELOPE_KEK_WRAP,
    workspace_id: workspaceId,
    target_user_id: targetUserId,
    key_version: keyVersion,
    sender_device_id: senderDeviceId,
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
