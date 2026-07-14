import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { WorkerKeyState } from "../state";
import { evictCachedKek, getCachedKek, setActiveKekVersion, setCachedKek } from "../state";
import { buildOfflineKekCacheAad } from "../../aad";
import { base64UrlDecode, base64UrlEncode, randomBytes } from "../../encoding";
import { blake3Base64Url } from "../../hash";
import { canonicalizeStrictBytes, parseJsonStrictBytes, type StrictJsonValue } from "../../jcs";
import {
  dskDecrypt,
  dskEncrypt,
  type HandlerPayload,
  requireDeviceHybridEncryptionPrivateKeyMaterial,
  requireDeviceHybridSigningPrivateKeyMaterial,
  requireDsk,
  requireIdentityHybridEncryptionPrivateKeyMaterial,
  requireKekForWorkspace,
  requireUmk,
} from "./utils";
import {
  createSignedPqWrap,
  finalizeSignedPqWrapOperationCheckpoint,
  openSignedPqWrap,
  signedPqWrapRecordFromEnvelope,
  type SignedPqWrapRecord,
} from "../../signed-pq-wrap";
import {
  beginInitialAkeUmkDelivery,
  beginInitialAkeKekDelivery,
  beginInitialAkeDeviceStateTransferDelivery,
  decodeInitialAkeRecord,
  finalizeInitialAkeDelivery,
  generateInitialAkeResponderPrekey,
  openInitialAkeUmkDelivery,
  respondToInitialAkeOffer,
  type InitialAkeArtifact,
  type InitialAkeOffer,
  type InitialAkeResponderConfirmation,
  type InitialAkeResponderPrekeyRecord,
  type InitialKeyDeliveryRecord,
} from "../../initial-ake";
import {
  computeHybridEncryptionKeyId,
  publicHybridEncryptionMaterialFromPrivate,
  type HybridEncryptionPublicKeyMaterial,
} from "../../hybrid-encryption";
import {
  computeSigningKeyId,
  publicKeyMaterialFromPrivate,
  type HybridSigningPrivateKeyMaterial,
  type HybridSigningPublicKeyMaterial,
} from "../../signature";
import {
  deleteDskStoreValueInWorker,
  loadDskStoreValueInWorker,
  loadDskStoreValueStrictInWorker,
  storeDskStoreValueInWorker,
} from "./dsk-idb";
import { installManagedShareSecretsFromBackup } from "./dek";
import { verifyWorkspaceSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";
import {
  recipientDeliveryOperationProof,
  verifyRecipientDeliveryAdmission,
  type RecipientDeliveryAdmissionProof,
  type VerifiedRecipientDeliveryAdmission,
} from "@/shared/lib/anti-rollback/key-directory-pin/recipient-delivery-admission";

const invitationBootstrapSuite = "refmd-v2-invitation-bootstrap-xchacha20poly1305";
const workspaceInvitationBootstrapProtocol = "refmd.workspace-invitation-bootstrap";
const guestInvitationBootstrapProtocol = "refmd.guest-invitation-bootstrap";
const hkdfZeroSalt = new Uint8Array(32);
const OFFLINE_KEK_KEY_PREFIX = "refmd-offline-key:kek:";
const OFFLINE_KEK_INDEX_KEY = "refmd-offline-key:kek-index";
const GUEST_SHARE_KEY_PREFIX = "refmd-guest-share-key";

type OfflineKekStoredEntry = {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
  keyVersion: number;
  cachedAt: number;
};

type GuestShareKeyMetadata = {
  shareId: string;
  scopeKind: "document" | "folder";
  scopeId: string;
  permission: "view" | "edit";
  shareKeyVersion: number;
  dekVersion: number;
};

type GuestShareKeyStoredEntry = GuestShareKeyMetadata & {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
};

function assertRecord(value: unknown, code: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

function assertExactKeys(record: Record<string, unknown>, keys: string[], code: string): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(code);
  }
}

function assertString(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function assertPositiveInteger(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(code);
  }
  return value;
}

function assertInvitationBootstrapProtocol(value: unknown): string {
  if (
    value !== workspaceInvitationBootstrapProtocol &&
    value !== guestInvitationBootstrapProtocol
  ) {
    throw new Error("invitation_bootstrap_protocol_invalid");
  }
  return value;
}

function deriveInvitationBootstrapRecipientKey(bootstrapSecret: string): Uint8Array {
  const secret = base64UrlDecode(bootstrapSecret);
  if (secret.length !== 32) throw new Error("invitation_bootstrap_secret_invalid");
  return hkdf(
    sha256,
    secret,
    hkdfZeroSalt,
    new TextEncoder().encode("refmd.invitation-bootstrap-package-key-recipient.v1"),
    32,
  );
}

function invitationPackageAad(envelopeAad: Record<string, unknown>): Uint8Array {
  return canonicalizeStrictBytes(envelopeAad as StrictJsonValue);
}

function assertInvitationCiphertext(value: unknown, code: string): Record<string, unknown> {
  const record = assertRecord(value, code);
  assertExactKeys(record, ["ciphertext", "nonce"], code);
  assertString(record.ciphertext, code);
  assertString(record.nonce, code);
  return record;
}

function assertInvitationRecipientWrap(value: unknown): Record<string, unknown> {
  const record = assertRecord(value, "invitation_bootstrap_recipient_wrap_invalid");
  if (record.delivery_mode !== "known_recipient") {
    return assertInvitationCiphertext(value, "invitation_bootstrap_recipient_wrap_invalid");
  }
  assertExactKeys(
    record,
    ["delivery_mode", "recipient_user_id", "sender_signing_public_key_material", "wraps"],
    "invitation_bootstrap_recipient_wrap_invalid",
  );
  assertString(record.recipient_user_id, "invitation_bootstrap_recipient_wrap_invalid");
  if (!Array.isArray(record.wraps)) {
    throw new Error("invitation_bootstrap_recipient_wrap_invalid");
  }
  record.wraps.forEach((wrap) => signedPqWrapRecordFromEnvelope(wrap));
  return record;
}

function assertInvitationMaintenanceWrap(value: unknown): Record<string, unknown> {
  const record = assertRecord(value, "invitation_bootstrap_maintenance_wrap_invalid");
  assertExactKeys(
    record,
    ["ciphertext", "key_version", "nonce"],
    "invitation_bootstrap_maintenance_wrap_invalid",
  );
  assertPositiveInteger(record.key_version, "invitation_bootstrap_maintenance_wrap_invalid");
  assertString(record.ciphertext, "invitation_bootstrap_maintenance_wrap_invalid");
  assertString(record.nonce, "invitation_bootstrap_maintenance_wrap_invalid");
  return record;
}

function assertGuestInvitationKeyVersionContext(
  value: unknown,
  scopeKind: string,
): Record<string, unknown> {
  const record = assertRecord(value, "guest_invitation_bootstrap_key_context_invalid");
  assertExactKeys(
    record,
    ["dek_version", "share_key_version", "workspace_kek_version"],
    "guest_invitation_bootstrap_key_context_invalid",
  );
  const workspaceKekVersion = record.workspace_kek_version;
  const shareKeyVersion = record.share_key_version;
  const dekVersion = record.dek_version;

  if (scopeKind === "workspace") {
    assertPositiveInteger(workspaceKekVersion, "guest_invitation_bootstrap_key_context_invalid");
    if (shareKeyVersion !== "NOT_APPLICABLE" || dekVersion !== "NOT_APPLICABLE") {
      throw new Error("guest_invitation_bootstrap_key_context_invalid");
    }
    return record;
  }

  if (workspaceKekVersion !== "NOT_APPLICABLE") {
    throw new Error("guest_invitation_bootstrap_key_context_invalid");
  }
  const shareKeyApplies =
    typeof shareKeyVersion === "number" &&
    Number.isSafeInteger(shareKeyVersion) &&
    shareKeyVersion > 0;
  const dekApplies =
    typeof dekVersion === "number" && Number.isSafeInteger(dekVersion) && dekVersion > 0;
  if (
    (!shareKeyApplies && shareKeyVersion !== "NOT_APPLICABLE") ||
    (!dekApplies && dekVersion !== "NOT_APPLICABLE") ||
    (!shareKeyApplies && !dekApplies)
  ) {
    throw new Error("guest_invitation_bootstrap_key_context_invalid");
  }
  return record;
}

function assertInvitationBootstrapAad(
  aad: Record<string, unknown>,
  protocol: string,
  workspaceId: string,
): void {
  if (protocol === workspaceInvitationBootstrapProtocol) {
    assertExactKeys(
      aad,
      [
        "invitation_id",
        "invited_email",
        "delivery_mode",
        "recipient_user_id",
        "recipient_device_ids",
        "key_version_context",
        "protocol",
        "role_id",
        "suite_id",
        "token_hash",
        "version",
        "workspace_id",
      ],
      "invitation_bootstrap_aad_invalid",
    );
    const keyContext = assertRecord(aad.key_version_context, "invitation_bootstrap_aad_invalid");
    assertExactKeys(keyContext, ["workspace_kek_version"], "invitation_bootstrap_aad_invalid");
    assertPositiveInteger(keyContext.workspace_kek_version, "invitation_bootstrap_aad_invalid");
    if (
      aad.protocol !== workspaceInvitationBootstrapProtocol ||
      aad.version !== 1 ||
      aad.suite_id !== invitationBootstrapSuite ||
      aad.workspace_id !== workspaceId
    ) {
      throw new Error("invitation_bootstrap_aad_invalid");
    }
    assertString(aad.invitation_id, "invitation_bootstrap_aad_invalid");
    assertString(aad.role_id, "invitation_bootstrap_aad_invalid");
    assertString(aad.invited_email, "invitation_bootstrap_aad_invalid");
    assertString(aad.token_hash, "invitation_bootstrap_aad_invalid");
    assertInvitationDeliveryAad(aad);
    return;
  }

  assertExactKeys(
    aad,
    [
      "guest_invitation_id",
      "key_version_context",
      "permission",
      "delivery_mode",
      "recipient_user_id",
      "recipient_device_ids",
      "protocol",
      "scope_id",
      "scope_kind",
      "suite_id",
      "token_hash",
      "version",
      "workspace_id",
    ],
    "guest_invitation_bootstrap_aad_invalid",
  );
  const scopeKind = assertString(aad.scope_kind, "guest_invitation_bootstrap_aad_invalid");
  if (
    scopeKind !== "workspace" &&
    scopeKind !== "document" &&
    scopeKind !== "folder" &&
    scopeKind !== "share"
  ) {
    throw new Error("guest_invitation_bootstrap_aad_invalid");
  }
  assertGuestInvitationKeyVersionContext(aad.key_version_context, scopeKind);
  if (
    aad.protocol !== guestInvitationBootstrapProtocol ||
    aad.version !== 1 ||
    aad.suite_id !== invitationBootstrapSuite ||
    aad.workspace_id !== workspaceId ||
    (aad.permission !== "view" && aad.permission !== "edit")
  ) {
    throw new Error("guest_invitation_bootstrap_aad_invalid");
  }
  assertString(aad.guest_invitation_id, "guest_invitation_bootstrap_aad_invalid");
  assertString(aad.scope_id, "guest_invitation_bootstrap_aad_invalid");
  assertString(aad.token_hash, "guest_invitation_bootstrap_aad_invalid");
  assertInvitationDeliveryAad(aad);
}

function assertInvitationDeliveryAad(aad: Record<string, unknown>): void {
  const deviceIds = aad.recipient_device_ids;
  if (!Array.isArray(deviceIds) || !deviceIds.every((deviceId) => typeof deviceId === "string")) {
    throw new Error("invitation_bootstrap_recipient_binding_invalid");
  }
  if (aad.delivery_mode === "unknown_fragment") {
    if (aad.recipient_user_id !== "NOT_APPLICABLE" || deviceIds.length !== 0) {
      throw new Error("invitation_bootstrap_recipient_binding_invalid");
    }
    return;
  }
  if (
    aad.delivery_mode !== "known_recipient" ||
    typeof aad.recipient_user_id !== "string" ||
    aad.recipient_user_id.length === 0 ||
    deviceIds.length === 0 ||
    new Set(deviceIds).size !== deviceIds.length
  ) {
    throw new Error("invitation_bootstrap_recipient_binding_invalid");
  }
}

function assertInvitationBootstrapPackage(bootstrap: Record<string, unknown>): {
  protocol: string;
  workspaceId: string;
  keyVersion: number;
  aad: Record<string, unknown>;
  encryptedPayload: Record<string, unknown>;
  recipientWrap: Record<string, unknown>;
} {
  const protocol = assertInvitationBootstrapProtocol(bootstrap.protocol);
  const packageKeys = [
    "aad",
    "encrypted_payload",
    "key_version",
    "package_key_maintenance_wrap",
    "package_key_recipient_wrap",
    "protocol",
    "suite_id",
    "version",
    "workspace_id",
  ];
  assertExactKeys(bootstrap, packageKeys, "invitation_bootstrap_package_invalid");
  const workspaceId = assertString(bootstrap.workspace_id, "invitation_bootstrap_package_invalid");
  const keyVersion = assertPositiveInteger(
    bootstrap.key_version,
    "invitation_bootstrap_package_invalid",
  );
  if (bootstrap.version !== 1 || bootstrap.suite_id !== invitationBootstrapSuite) {
    throw new Error("invitation_bootstrap_package_invalid");
  }
  const aad = assertRecord(bootstrap.aad, "invitation_bootstrap_aad_invalid");
  assertInvitationBootstrapAad(aad, protocol, workspaceId);
  const encryptedPayload = assertInvitationCiphertext(
    bootstrap.encrypted_payload,
    "invitation_bootstrap_payload_invalid",
  );
  const recipientWrap = assertInvitationRecipientWrap(bootstrap.package_key_recipient_wrap);
  assertInvitationRecipientWrapMatchesAad(recipientWrap, aad);
  const maintenanceWrap = assertInvitationMaintenanceWrap(bootstrap.package_key_maintenance_wrap);
  assertInvitationBootstrapMaintenanceContext(protocol, aad, keyVersion, maintenanceWrap);
  return { protocol, workspaceId, keyVersion, aad, encryptedPayload, recipientWrap };
}

function assertInvitationRecipientWrapMatchesAad(
  recipientWrap: Record<string, unknown>,
  aad: Record<string, unknown>,
): void {
  if (aad.delivery_mode === "unknown_fragment") {
    if (recipientWrap.delivery_mode === "known_recipient") {
      throw new Error("invitation_bootstrap_recipient_binding_invalid");
    }
    return;
  }
  if (
    recipientWrap.delivery_mode !== "known_recipient" ||
    recipientWrap.recipient_user_id !== aad.recipient_user_id
  ) {
    throw new Error("invitation_bootstrap_recipient_binding_invalid");
  }
  const expectedDeviceIds = [...(aad.recipient_device_ids as string[])].sort();
  const wraps = recipientWrap.wraps as unknown[];
  if (wraps.length === 0) return;
  const wrapDeviceIds = wraps
    .map((wrap) => signedPqWrapRecordFromEnvelope(wrap))
    .map((wrap) => (wrap.resource as { recipient_device_id: string }).recipient_device_id)
    .sort();
  if (
    wrapDeviceIds.length !== expectedDeviceIds.length ||
    wrapDeviceIds.some((deviceId, index) => deviceId !== expectedDeviceIds[index])
  ) {
    throw new Error("invitation_bootstrap_recipient_binding_invalid");
  }
}

function assertInvitationBootstrapMaintenanceContext(
  protocol: string,
  aad: Record<string, unknown>,
  keyVersion: number,
  maintenanceWrap: Record<string, unknown>,
): void {
  if (maintenanceWrap.key_version !== keyVersion) {
    throw new Error("invitation_bootstrap_maintenance_wrap_invalid");
  }
  const keyContext = assertRecord(
    aad.key_version_context,
    "invitation_bootstrap_maintenance_wrap_invalid",
  );
  if (protocol === workspaceInvitationBootstrapProtocol || aad.scope_kind === "workspace") {
    if (keyContext.workspace_kek_version !== keyVersion) {
      throw new Error("invitation_bootstrap_maintenance_wrap_invalid");
    }
    return;
  }
  const scopedVersions = [keyContext.share_key_version, keyContext.dek_version].filter(
    (value): value is number => typeof value === "number",
  );
  if (
    !scopedVersions.includes(keyVersion) ||
    keyContext.workspace_kek_version !== "NOT_APPLICABLE"
  ) {
    throw new Error("invitation_bootstrap_maintenance_wrap_invalid");
  }
}

function validateInvitationRedeemAuthority(
  value: unknown,
  expectedOwnerId: string,
): {
  privateMaterial: HybridSigningPrivateKeyMaterial;
  publicMaterial: HybridSigningPublicKeyMaterial;
  signingKeyId: string;
} {
  const record = assertRecord(value, "invitation_redeem_authority_owner_mismatch");
  if (record.owner_kind !== "invitation_redeem_authority" || record.owner_id !== expectedOwnerId) {
    throw new Error("invitation_redeem_authority_owner_mismatch");
  }
  const privateMaterial = record as unknown as HybridSigningPrivateKeyMaterial;
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  return {
    privateMaterial,
    publicMaterial,
    signingKeyId: computeSigningKeyId(publicMaterial),
  };
}

function assertInvitationBootstrapPlaintext(
  plaintext: Record<string, unknown>,
  params: {
    protocol: string;
    workspaceId: string;
    keyVersion: number;
    aad: Record<string, unknown>;
  },
): {
  sanitizedPlaintext: Record<string, unknown>;
  encodedKek: string | null;
  encodedGuestShareKey: string | null;
  redeemAuthority: {
    ownerId: string;
    privateMaterial: HybridSigningPrivateKeyMaterial;
    publicMaterial: HybridSigningPublicKeyMaterial;
    signingKeyId: string;
  };
} {
  if (
    plaintext.protocol !== params.protocol ||
    plaintext.version !== 1 ||
    plaintext.workspace_id !== params.workspaceId
  ) {
    throw new Error("invitation_bootstrap_plaintext_mismatch");
  }

  if (params.protocol === workspaceInvitationBootstrapProtocol) {
    const includesWorkspaceKek = params.aad.delivery_mode === "unknown_fragment";
    assertExactKeys(
      plaintext,
      [
        "invitation_id",
        "invited_email",
        "kek_version",
        "protocol",
        "redeem_authority_private_key_material",
        "role_id",
        "version",
        "workspace_id",
        ...(includesWorkspaceKek ? ["workspace_kek"] : []),
        "workspace_key_directory_checkpoint",
        "workspace_pin_bootstrap",
        "workspace_pin_bootstrap_hash",
      ],
      "invitation_bootstrap_plaintext_invalid",
    );
    if (
      plaintext.invitation_id !== params.aad.invitation_id ||
      plaintext.role_id !== params.aad.role_id ||
      plaintext.invited_email !== params.aad.invited_email ||
      plaintext.kek_version !== params.keyVersion
    ) {
      throw new Error("invitation_bootstrap_plaintext_mismatch");
    }
    const encodedKek = includesWorkspaceKek
      ? assertString(plaintext.workspace_kek, "invitation_bootstrap_kek_invalid")
      : null;
    const redeemAuthority = validateInvitationRedeemAuthority(
      plaintext.redeem_authority_private_key_material,
      plaintext.invitation_id as string,
    );
    return {
      sanitizedPlaintext: sanitizedInvitationBootstrapPlaintext(plaintext),
      encodedKek,
      encodedGuestShareKey: null,
      redeemAuthority: {
        ownerId: plaintext.invitation_id as string,
        ...redeemAuthority,
      },
    };
  }

  const scopeKind = assertString(
    plaintext.scope_kind,
    "guest_invitation_bootstrap_plaintext_invalid",
  );
  if (
    scopeKind !== "workspace" &&
    scopeKind !== "document" &&
    scopeKind !== "folder" &&
    scopeKind !== "share"
  ) {
    throw new Error("guest_invitation_bootstrap_scope_invalid");
  }
  const workspaceScope = scopeKind === "workspace";
  const includesWorkspaceKek = workspaceScope && params.aad.delivery_mode === "unknown_fragment";
  const includesGuestShareKey = !workspaceScope && params.aad.delivery_mode === "unknown_fragment";
  assertExactKeys(
    plaintext,
    [
      "guest_invitation_id",
      "key_version_context",
      "permission",
      "protocol",
      "redeem_authority_private_key_material",
      "scope_id",
      "scope_kind",
      "version",
      "workspace_id",
      "workspace_key_directory_checkpoint",
      ...(includesWorkspaceKek ? ["workspace_kek"] : []),
      ...(includesGuestShareKey ? ["guest_share_key"] : []),
      "workspace_pin_bootstrap",
      "workspace_pin_bootstrap_hash",
    ],
    "guest_invitation_bootstrap_plaintext_invalid",
  );
  const keyContext = assertGuestInvitationKeyVersionContext(
    plaintext.key_version_context,
    scopeKind,
  );
  const aadKeyContext = params.aad.key_version_context as Record<string, unknown>;
  if (
    plaintext.guest_invitation_id !== params.aad.guest_invitation_id ||
    plaintext.scope_kind !== params.aad.scope_kind ||
    plaintext.scope_id !== params.aad.scope_id ||
    plaintext.permission !== params.aad.permission ||
    keyContext.workspace_kek_version !== aadKeyContext.workspace_kek_version ||
    keyContext.share_key_version !== aadKeyContext.share_key_version ||
    keyContext.dek_version !== aadKeyContext.dek_version
  ) {
    throw new Error("guest_invitation_bootstrap_plaintext_mismatch");
  }
  const encodedKek = includesWorkspaceKek
    ? assertString(plaintext.workspace_kek, "invitation_bootstrap_kek_invalid")
    : null;
  const encodedGuestShareKey = includesGuestShareKey
    ? assertString(plaintext.guest_share_key, "invitation_bootstrap_share_key_invalid")
    : null;
  const redeemAuthority = validateInvitationRedeemAuthority(
    plaintext.redeem_authority_private_key_material,
    plaintext.guest_invitation_id as string,
  );
  return {
    sanitizedPlaintext: sanitizedInvitationBootstrapPlaintext(plaintext),
    encodedKek,
    encodedGuestShareKey,
    redeemAuthority: {
      ownerId: plaintext.guest_invitation_id as string,
      ...redeemAuthority,
    },
  };
}

function sanitizedInvitationBootstrapPlaintext(
  plaintext: Record<string, unknown>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(plaintext).filter(
      ([key]) =>
        key !== "workspace_kek" &&
        key !== "guest_share_key" &&
        key !== "redeem_authority_private_key_material",
    ),
  );
}

export function handleGenerateKek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = (p.keyVersion as number) ?? 1;
  const existing = getCachedKek(state, workspaceId, keyVersion);
  if (existing) {
    setActiveKekVersion(state, workspaceId, keyVersion);
    return { keyVersion };
  }
  const kek = randomBytes(32);
  setCachedKek(state, workspaceId, kek, keyVersion);
  setActiveKekVersion(state, workspaceId, keyVersion);
  return { keyVersion };
}

export function handleResolveKek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number | undefined;
  const cached = getCachedKek(state, workspaceId, keyVersion);
  if (!cached) {
    return { found: false };
  }
  return { found: true, keyVersion: cached.keyVersion };
}

export function handleSetActiveKekVersion(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  setActiveKekVersion(state, workspaceId, keyVersion);
  return { status: "ok" };
}

export async function handleDeleteKekVersion(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const workspaceId = assertString(p.workspaceId, "workspace_id_invalid");
  const keyVersion = assertPositiveInteger(p.keyVersion, "kek_key_version_invalid");
  if (state.activeKekVersions.get(workspaceId) === keyVersion) {
    throw new Error("active_kek_version_deletion_forbidden");
  }

  const memoryDeleted = evictCachedKek(state, workspaceId, keyVersion);
  const storageKey = offlineKekKey(workspaceId);
  const persisted = await loadDskStoreValueStrictInWorker<OfflineKekStoredEntry>(storageKey);
  const offlineDeleted = persisted?.keyVersion === keyVersion;
  if (offlineDeleted) {
    await deleteDskStoreValueInWorker(storageKey);
    await removeOfflineKekIndex(workspaceId);
  }

  if (getCachedKek(state, workspaceId, keyVersion)) {
    throw new Error("kek_memory_deletion_failed");
  }
  const remaining = await loadDskStoreValueStrictInWorker<OfflineKekStoredEntry>(storageKey);
  if (remaining?.keyVersion === keyVersion) {
    throw new Error("kek_persistent_deletion_failed");
  }

  return { memoryDeleted, offlineDeleted, keyVersion };
}

export function handleCreateSignedPqKekWrap(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const { kek } = requireKekForWorkspace(state, workspaceId, keyVersion);
  const purpose = signedPqWrapPurpose(p.purpose);
  return createSignedPqWrap({
    purpose,
    plaintext: kek,
    recipientPublicKeyMaterial:
      p.recipientPublicKeyMaterial as unknown as HybridEncryptionPublicKeyMaterial,
    senderSigningPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
    senderUserId: p.senderUserId as string,
    senderDeviceId: p.senderDeviceId as string,
    resource: p.resource as never,
    eventScope: p.eventScope as never,
    operationCheckpoint: p.operationCheckpoint as never,
    eventPrevious: p.eventPrevious as never,
    recipientKeyCheckpoint: p.recipientKeyCheckpoint as never,
  });
}

export function handleCreateSignedPqShareLinkSecretBackupWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const shareSlug = p.shareSlug as string;
  const secrets = state.shareSecrets.get(shareSlug);
  const shareCapabilitySecret = secrets?.capabilitySecret;
  if (!shareCapabilitySecret) throw new Error("share_capability_secret_unavailable");

  const shareCapabilitySecretBase64 = base64UrlEncode(shareCapabilitySecret);
  const shareCapabilitySecretCommitment = p.shareCapabilitySecretCommitment as string;
  if (blake3Base64Url(shareCapabilitySecret) !== shareCapabilitySecretCommitment) {
    throw new Error("share_capability_secret_commitment_mismatch");
  }

  const passwordProtected = p.passwordProtected === true;
  const passwordCapabilitySecret = secrets?.passwordCapabilitySecret;
  const requiredPasswordCapabilitySecret = passwordProtected
    ? requireSecret(passwordCapabilitySecret, "password_capability_secret_unavailable")
    : null;
  const passwordCapabilitySecretBase64 = requiredPasswordCapabilitySecret
    ? base64UrlEncode(requiredPasswordCapabilitySecret)
    : "none";
  const passwordCapabilitySecretCommitment = p.passwordCapabilitySecretCommitment as string;
  if (
    requiredPasswordCapabilitySecret &&
    blake3Base64Url(requiredPasswordCapabilitySecret) !== passwordCapabilitySecretCommitment
  ) {
    throw new Error("password_capability_secret_commitment_mismatch");
  }

  const plaintext = {
    protocol: "refmd.share-link-secret-backup-plaintext",
    version: 1,
    workspace_id: p.workspaceId as string,
    share_id: p.shareId as string,
    token_hash: p.tokenHash as string,
    scope_kind: p.scopeKind as string,
    scope_id: p.scopeId as string,
    permission: p.permission as string,
    password_protected: passwordProtected,
    created_event_hash: p.createdEventHash as string,
    share_slug: shareSlug,
    share_capability_secret: shareCapabilitySecretBase64,
    share_capability_secret_commitment: shareCapabilitySecretCommitment,
    workspace_pin_bootstrap_hash: p.workspacePinBootstrapHash as string,
    password_capability_secret: passwordCapabilitySecretBase64,
    password_capability_secret_commitment: passwordCapabilitySecretCommitment,
  };

  return createSignedPqWrap({
    purpose: "share_link_secret_backup_wrap",
    plaintext: canonicalizeStrictBytes(plaintext as StrictJsonValue),
    recipientPublicKeyMaterial:
      p.recipientPublicKeyMaterial as unknown as HybridEncryptionPublicKeyMaterial,
    senderSigningPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
    senderUserId: p.senderUserId as string,
    senderDeviceId: p.senderDeviceId as string,
    resource: p.resource as never,
    eventScope: p.eventScope as never,
    operationCheckpoint: p.operationCheckpoint as never,
  });
}

export function handleCreateSignedPqGuestInvitationShareKeyWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const shareSlug = assertString(p.shareSlug, "share_slug_invalid");
  const shareKey = state.shareSecrets.get(shareSlug)?.dekEncryptionKey;
  if (!shareKey || shareKey.length !== 32) {
    throw new Error("share_dek_encryption_key_required");
  }

  return createSignedPqWrap({
    purpose: "guest_invitation_share_key_wrap",
    plaintext: shareKey,
    recipientPublicKeyMaterial:
      p.recipientPublicKeyMaterial as unknown as HybridEncryptionPublicKeyMaterial,
    senderSigningPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
    senderUserId: p.senderUserId as string,
    senderDeviceId: p.senderDeviceId as string,
    resource: p.resource as never,
    eventScope: p.eventScope as never,
    operationCheckpoint: p.operationCheckpoint as never,
    eventPrevious: p.eventPrevious as never,
    recipientKeyCheckpoint: p.recipientKeyCheckpoint as never,
  });
}

export function handleFinalizeSignedPqWrapOperationCheckpoint(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return finalizeSignedPqWrapOperationCheckpoint({
    record: p.record as SignedPqWrapRecord,
    operationCheckpoint: p.operationCheckpoint as never,
    senderSigningPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
  });
}

function requireSecret(secret: Uint8Array | undefined, error: string): Uint8Array {
  if (!secret) throw new Error(error);
  return secret;
}

function signedPqWrapPurpose(value: unknown) {
  switch (value) {
    case "workspace_device_kek_wrap":
    case "workspace_member_kek_wrap":
    case "workspace_invitation_kek_wrap":
    case "guest_invitation_workspace_kek_wrap":
      return value;
    default:
      throw new Error("signed_pq_wrap_purpose_invalid");
  }
}

export function handleGenerateInitialAkeResponderPrekey(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const purpose = initialAkePurpose(p.purpose);
  const result = generateInitialAkeResponderPrekey({
    purpose,
    operationId: requiredString(p.operationId, "operation_id_invalid"),
    userId: requiredString(p.userId, "user_id_invalid"),
    deviceId: requiredString(p.deviceId, "device_id_invalid"),
    serverChallenge: requiredString(p.serverChallenge, "server_challenge_invalid"),
    issuedAtEventSequence: positiveInteger(
      p.issuedAtEventSequence,
      "issued_at_event_sequence_invalid",
    ),
    expiresEventSequence: positiveInteger(p.expiresEventSequence, "expires_event_sequence_invalid"),
    signingPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
  });
  state.initialAkeResponderPrekeys.set(
    initialAkePrekeyStateKey(
      result.privatePrekey.purpose,
      result.privatePrekey.operation_id,
      result.privatePrekey.prekey_id,
    ),
    result.privatePrekey,
  );
  return result.record;
}

function initialAkePurpose(value: unknown) {
  switch (value) {
    case "umk_distribution":
    case "device_approval_kek_initial":
    case "trust_transfer":
      return value;
    default:
      throw new Error("responder_prekey_purpose_invalid");
  }
}

function positiveInteger(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error(code);
  }
  return value;
}

function requiredString(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

export function handleBeginInitialAkeUmkDelivery(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const senderEncryptionKeyId = currentDeviceEncryptionKeyId(state);
  const result = beginInitialAkeUmkDelivery({
    umk: requireUmk(state),
    userId: p.userId as string,
    senderDeviceId: p.senderDeviceId as string,
    senderEncryptionKeyId,
    recipientDeviceId: p.recipientDeviceId as string,
    recipientEncryptionKeyId: p.recipientEncryptionKeyId as string,
    responderPrekey: p.responderPrekey as unknown as InitialAkeResponderPrekeyRecord,
    responderSigningPublicKeyMaterial:
      p.responderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    senderSigningPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
    resourceHash: p.resourceHash as string,
    keyCheckpointHash: p.keyCheckpointHash as string,
    keyEventHeadHash: p.keyEventHeadHash as string,
    pendingRegistrationBindingHash: p.pendingRegistrationBindingHash as string,
  });
  state.initialAkeInitiatorSessions.set(result.offer.transcript_hash, result.initiatorState);
  return result.offer;
}

export function handleBeginInitialAkeKekDelivery(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const { kek } = requireKekForWorkspace(state, workspaceId, keyVersion);
  const senderEncryptionKeyId = currentDeviceEncryptionKeyId(state);
  const result = beginInitialAkeKekDelivery({
    kek,
    workspaceId,
    keyVersion,
    userId: p.userId as string,
    senderDeviceId: p.senderDeviceId as string,
    senderEncryptionKeyId,
    recipientDeviceId: p.recipientDeviceId as string,
    recipientEncryptionKeyId: p.recipientEncryptionKeyId as string,
    responderPrekey: p.responderPrekey as unknown as InitialAkeResponderPrekeyRecord,
    responderSigningPublicKeyMaterial:
      p.responderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    senderSigningPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
    resourceHash: p.resourceHash as string,
    keyCheckpointHash: p.keyCheckpointHash as string,
    keyEventHeadHash: p.keyEventHeadHash as string,
    userCheckpointHash: p.userCheckpointHash as string,
    workspaceCheckpointHash: p.workspaceCheckpointHash as string,
    workspaceEventHeadHash: p.workspaceEventHeadHash as string,
    pendingRegistrationBindingHash: p.pendingRegistrationBindingHash as string,
  });
  state.initialAkeInitiatorSessions.set(result.offer.transcript_hash, result.initiatorState);
  return result.offer;
}

export function handleBeginInitialAkeDeviceStateTransferDelivery(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const senderEncryptionKeyId = currentDeviceEncryptionKeyId(state);
  const result = beginInitialAkeDeviceStateTransferDelivery({
    deviceStateBundle: p.deviceStateBundle as never,
    userId: p.userId as string,
    senderDeviceId: p.senderDeviceId as string,
    senderEncryptionKeyId,
    recipientDeviceId: p.recipientDeviceId as string,
    recipientEncryptionKeyId: p.recipientEncryptionKeyId as string,
    responderPrekey: p.responderPrekey as unknown as InitialAkeResponderPrekeyRecord,
    responderSigningPublicKeyMaterial:
      p.responderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    senderSigningPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
    resourceHash: p.resourceHash as string,
    keyCheckpointHash: p.keyCheckpointHash as string,
    keyEventHeadHash: p.keyEventHeadHash as string,
    workspacePinsHash: p.workspacePinsHash as string,
    documentRollbackPinSetHash: p.documentRollbackPinSetHash as string,
    pendingRegistrationBindingHash: p.pendingRegistrationBindingHash as string,
  });
  state.initialAkeInitiatorSessions.set(result.offer.transcript_hash, result.initiatorState);
  return result.offer;
}

export function handleRespondToInitialAkeOffer(state: WorkerKeyState, p: HandlerPayload): unknown {
  const offer = decodeInitialAkeRecord<InitialAkeOffer>(p.offer);
  const prekeyStateKey = initialAkePrekeyStateKeyFromTranscript(offer);
  const privatePrekey = state.initialAkeResponderPrekeys.get(prekeyStateKey);
  if (!privatePrekey) throw new Error("initial_ake_responder_prekey_missing");
  try {
    const result = respondToInitialAkeOffer({
      offer,
      privatePrekey,
      senderSigningPublicKeyMaterial:
        p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    });
    state.initialAkeResponderSessions.set(offer.transcript_hash, result.responderState);
    return result.response;
  } finally {
    privatePrekey.x25519_private.fill(0);
    privatePrekey.mlkem768_private.fill(0);
    state.initialAkeResponderPrekeys.delete(prekeyStateKey);
  }
}

export function handleFinalizeInitialAkeDelivery(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const response = decodeInitialAkeRecord<InitialAkeResponderConfirmation>(p.response);
  const initiatorState = state.initialAkeInitiatorSessions.get(response.transcript_hash);
  if (!initiatorState) throw new Error("initial_ake_initiator_session_missing");
  try {
    return finalizeInitialAkeDelivery({
      initiatorState,
      response,
      senderSigningPrivateKeyMaterial: requireDeviceHybridSigningPrivateKeyMaterial(state),
    });
  } finally {
    initiatorState.secret.fill(0);
    state.initialAkeInitiatorSessions.delete(response.transcript_hash);
  }
}

function currentDeviceEncryptionKeyId(state: WorkerKeyState): string {
  const publicMaterial =
    state.deviceHybridEncryptionPublicKeyMaterial ??
    publicHybridEncryptionMaterialFromPrivate(
      requireDeviceHybridEncryptionPrivateKeyMaterial(state),
    );
  return computeHybridEncryptionKeyId(publicMaterial);
}

export async function handleOpenSignedPqDeviceKekWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const { record, verifiedOperation } = await verifySignedPqWrapOperationInWorker(p);
  if (
    record.purpose === "workspace_invitation_kek_wrap" ||
    record.purpose === "guest_invitation_workspace_kek_wrap" ||
    record.purpose === "guest_invitation_share_key_wrap"
  ) {
    throw new Error("recipient_delivery_admission_required");
  }
  if (record.purpose !== "workspace_device_kek_wrap") {
    throw new Error("signed_pq_wrap_purpose_invalid");
  }
  const senderSigningPublicKeyMaterial =
    p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial;
  const kek = openSignedPqWrap({
    record,
    senderSigningPublicKeyMaterial,
    recipientPrivateKeyMaterial: requireDeviceHybridEncryptionPrivateKeyMaterial(state),
    verifiedOperation,
  });
  const resource = record.resource as Record<string, unknown>;
  setCachedKek(state, resource.workspace_id as string, kek, resource.kek_version as number);
  return { status: "ok" };
}

export async function handleOpenRecipientBoundInvitationDeviceKekWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const admissionProof = p.recipientDeliveryAdmissionProof as unknown as
    | RecipientDeliveryAdmissionProof
    | undefined;
  if (!admissionProof) throw new Error("recipient_delivery_admission_required");
  const admission = await verifyRecipientDeliveryAdmission(admissionProof);
  const { record, verifiedOperation } = await verifySignedPqWrapOperationInWorker(p, admission);
  if (
    record.purpose !== "workspace_invitation_kek_wrap" &&
    record.purpose !== "guest_invitation_workspace_kek_wrap"
  ) {
    throw new Error("signed_pq_wrap_purpose_invalid");
  }
  assertRecipientDeliveryWrapBinding(record, admissionProof);
  const kek = openSignedPqWrap({
    record,
    senderSigningPublicKeyMaterial:
      p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    recipientPrivateKeyMaterial: requireDeviceHybridEncryptionPrivateKeyMaterial(state),
    verifiedOperation,
  });
  const resource = record.resource as Record<string, unknown>;
  setCachedKek(state, resource.workspace_id as string, kek, resource.kek_version as number);
  return { status: "ok" };
}

export async function handleOpenSignedPqMemberKekWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const { record, verifiedOperation } = await verifySignedPqWrapOperationInWorker(p);
  const senderSigningPublicKeyMaterial =
    p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial;
  const kek = openSignedPqWrap({
    record,
    senderSigningPublicKeyMaterial,
    recipientPrivateKeyMaterial: requireIdentityHybridEncryptionPrivateKeyMaterial(state),
    verifiedOperation,
  });
  const resource = record.resource as Record<string, unknown>;
  setCachedKek(state, resource.workspace_id as string, kek, resource.kek_version as number);
  return { status: "ok" };
}

export async function handleOpenSignedPqShareLinkSecretBackupWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const { record, verifiedOperation } = await verifySignedPqWrapOperationInWorker(p);
  if (record.purpose !== "share_link_secret_backup_wrap") {
    throw new Error("signed_pq_wrap_purpose_invalid");
  }
  const plaintext = openSignedPqWrap({
    record,
    senderSigningPublicKeyMaterial:
      p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    recipientPrivateKeyMaterial: requireDeviceHybridEncryptionPrivateKeyMaterial(state),
    verifiedOperation,
  });
  return {
    sharePathWithFragment: shareLinkSecretBackupPathWithFragment(
      state,
      record,
      plaintext,
      p.expectedShareId,
    ),
  };
}

export async function handleOpenSignedPqGuestInvitationShareKeyWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const admissionProof = p.recipientDeliveryAdmissionProof as unknown as
    | RecipientDeliveryAdmissionProof
    | undefined;
  if (!admissionProof) throw new Error("recipient_delivery_admission_required");
  const admission = await verifyRecipientDeliveryAdmission(admissionProof);
  const { record, verifiedOperation } = await verifySignedPqWrapOperationInWorker(p, admission);
  if (record.purpose !== "guest_invitation_share_key_wrap") {
    throw new Error("signed_pq_wrap_purpose_invalid");
  }
  assertRecipientDeliveryWrapBinding(record, admissionProof);
  const key = openSignedPqWrap({
    record,
    senderSigningPublicKeyMaterial:
      p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    recipientPrivateKeyMaterial: requireDeviceHybridEncryptionPrivateKeyMaterial(state),
    verifiedOperation,
  });
  const metadata = guestShareKeyMetadata(record.resource as Record<string, unknown>);
  installGuestShareKey(state, metadata, key);
  await persistGuestShareKey(state, metadata, key);
  key.fill(0);
  return { status: "ok" };
}

async function verifySignedPqWrapOperationInWorker(
  p: HandlerPayload,
  admission?: VerifiedRecipientDeliveryAdmission,
) {
  const unverifiedOperationProof = assertRecord(
    p.operationProof,
    "signed_pq_wrap_operation_proof_invalid",
  );
  const operationProof = admission
    ? recipientDeliveryOperationProof(admission, unverifiedOperationProof)
    : unverifiedOperationProof;
  const record = signedPqWrapRecordFromEnvelope(operationProof);
  if (record.event_scope.scope_kind !== "workspace") {
    throw new Error("signed_pq_wrap_workspace_scope_mismatch");
  }
  const verifiedOperation = await verifyWorkspaceSignedPqWrapOperation(
    record.event_scope.scope_id,
    operationProof,
  );
  return { record, verifiedOperation };
}

function assertRecipientDeliveryWrapBinding(
  record: SignedPqWrapRecord,
  proof: RecipientDeliveryAdmissionProof,
): void {
  const { attempt } = proof;
  const resource = record.resource as Record<string, unknown>;
  const common =
    resource.workspace_id === attempt.workspace_id &&
    resource.recipient_encryption_key_id === attempt.target_encryption_key_id &&
    record.recipient.encryption_key_id === attempt.target_encryption_key_id;
  const workspaceValid =
    record.purpose === "workspace_invitation_kek_wrap" &&
    attempt.context_kind === "workspace_invitation" &&
    resource.invitation_id === attempt.context_id &&
    resource.redeemed_user_id === attempt.target_user_id &&
    resource.redeemed_device_id === attempt.target_device_id;
  const guestValid =
    (record.purpose === "guest_invitation_workspace_kek_wrap" ||
      record.purpose === "guest_invitation_share_key_wrap") &&
    attempt.context_kind === "guest_invitation" &&
    resource.guest_invitation_id === attempt.context_id &&
    resource.guest_user_id === attempt.target_user_id &&
    resource.guest_device_id === attempt.target_device_id;
  if (!common || (!workspaceValid && !guestValid)) {
    throw new Error("recipient_delivery_wrap_binding_mismatch");
  }
}

export async function handleRestoreGuestInvitationShareKey(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const metadata = guestShareKeyMetadata({
    share_id: p.shareId,
    scope_kind: p.scopeKind,
    scope_id: p.scopeId,
    permission: p.permission,
    share_key_version: p.shareKeyVersion,
    dek_version: p.dekVersion,
  });
  const stored = await loadDskStoreValueStrictInWorker<GuestShareKeyStoredEntry>(
    guestShareKeyStorageKey(state, metadata.shareId),
  );
  if (!stored || !sameGuestShareKeyMetadata(stored, metadata)) return { restored: false };
  const key = await dskDecrypt(
    requireDsk(state),
    stored.ciphertext,
    stored.iv,
    guestShareKeyAad(state, metadata),
  );
  if (key.length !== 32) {
    key.fill(0);
    throw new Error("guest_share_key_invalid");
  }
  installGuestShareKey(state, metadata, key);
  key.fill(0);
  return { restored: true };
}

export async function handleCommitGuestInvitationShareKey(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const invitationId = assertString(p.invitationId, "guest_invitation_id_invalid");
  const key = state.pendingGuestInvitationShareKeys.get(invitationId);
  if (!key || key.length !== 32) throw new Error("guest_invitation_share_key_missing");
  const metadata = guestShareKeyMetadata({
    share_id: p.shareId,
    scope_kind: p.scopeKind,
    scope_id: p.scopeId,
    permission: p.permission,
    share_key_version: p.shareKeyVersion,
    dek_version: p.dekVersion,
  });
  installGuestShareKey(state, metadata, key);
  await persistGuestShareKey(state, metadata, key);
  key.fill(0);
  state.pendingGuestInvitationShareKeys.delete(invitationId);
  return { status: "ok" };
}

function guestShareKeyMetadata(resource: Record<string, unknown>): GuestShareKeyMetadata {
  const scopeKind = resource.scope_kind;
  const permission = resource.permission;
  if (scopeKind !== "document" && scopeKind !== "folder") {
    throw new Error("guest_share_scope_invalid");
  }
  if (permission !== "view" && permission !== "edit") {
    throw new Error("guest_share_permission_invalid");
  }
  return {
    shareId: assertString(resource.share_id, "guest_share_id_invalid"),
    scopeKind,
    scopeId: assertString(resource.scope_id, "guest_share_scope_invalid"),
    permission,
    shareKeyVersion: assertPositiveInteger(
      resource.share_key_version,
      "guest_share_key_version_invalid",
    ),
    dekVersion: assertPositiveInteger(resource.dek_version, "guest_share_dek_version_invalid"),
  };
}

function installGuestShareKey(
  state: WorkerKeyState,
  metadata: GuestShareKeyMetadata,
  key: Uint8Array,
): void {
  state.guestShareKeys.get(metadata.shareId)?.key.fill(0);
  state.guestShareKeys.set(metadata.shareId, { ...metadata, key: new Uint8Array(key) });
}

async function persistGuestShareKey(
  state: WorkerKeyState,
  metadata: GuestShareKeyMetadata,
  key: Uint8Array,
): Promise<void> {
  const encrypted = await dskEncrypt(requireDsk(state), key, guestShareKeyAad(state, metadata));
  await storeDskStoreValueInWorker(guestShareKeyStorageKey(state, metadata.shareId), {
    ...metadata,
    ...encrypted,
  } satisfies GuestShareKeyStoredEntry);
}

function guestShareKeyStorageKey(state: WorkerKeyState, shareId: string): string {
  return [
    GUEST_SHARE_KEY_PREFIX,
    assertString(state.userId, "guest_share_user_required"),
    assertString(state.deviceId, "guest_share_device_required"),
    shareId,
  ].join(":");
}

function guestShareKeyAad(state: WorkerKeyState, metadata: GuestShareKeyMetadata): Uint8Array {
  return canonicalizeStrictBytes({
    protocol: "refmd.guest-share-key-cache",
    version: 1,
    user_id: assertString(state.userId, "guest_share_user_required"),
    device_id: assertString(state.deviceId, "guest_share_device_required"),
    share_id: metadata.shareId,
    scope_kind: metadata.scopeKind,
    scope_id: metadata.scopeId,
    permission: metadata.permission,
    share_key_version: metadata.shareKeyVersion,
    dek_version: metadata.dekVersion,
  });
}

function sameGuestShareKeyMetadata(
  stored: GuestShareKeyStoredEntry,
  expected: GuestShareKeyMetadata,
): boolean {
  return (
    stored.shareId === expected.shareId &&
    stored.scopeKind === expected.scopeKind &&
    stored.scopeId === expected.scopeId &&
    stored.permission === expected.permission &&
    stored.shareKeyVersion === expected.shareKeyVersion &&
    stored.dekVersion === expected.dekVersion
  );
}

function shareLinkSecretBackupPathWithFragment(
  state: WorkerKeyState,
  record: ReturnType<typeof signedPqWrapRecordFromEnvelope>,
  plaintext: Uint8Array,
  expectedShareId: unknown,
): string {
  const decoded = parseJsonStrictBytes(plaintext) as Record<string, unknown>;
  const resource = record.resource as Record<string, unknown>;
  const shareSlug = requireStringField(decoded, "share_slug");
  const shareCapabilitySecret = requireStringField(decoded, "share_capability_secret");
  const workspacePinBootstrapHash = requireStringField(decoded, "workspace_pin_bootstrap_hash");
  const shareId = requireStringField(decoded, "share_id");
  const tokenHash = requireStringField(decoded, "token_hash");
  const shareCapabilitySecretCommitment = requireStringField(
    decoded,
    "share_capability_secret_commitment",
  );
  const passwordCapabilitySecretValue = requireStringField(decoded, "password_capability_secret");
  const passwordCapabilitySecretCommitment = requireStringField(
    decoded,
    "password_capability_secret_commitment",
  );
  const passwordProtected = decoded.password_protected === true;
  const capabilitySecret = base64UrlDecode(shareCapabilitySecret);
  const passwordCapabilitySecret = passwordProtected
    ? base64UrlDecode(passwordCapabilitySecretValue)
    : undefined;

  if (
    decoded.protocol !== "refmd.share-link-secret-backup-plaintext" ||
    decoded.version !== 1 ||
    shareId !== expectedShareId ||
    shareId !== resource.share_id ||
    tokenHash !== resource.token_hash ||
    workspacePinBootstrapHash !== resource.workspace_pin_bootstrap_hash ||
    shareCapabilitySecretCommitment !== resource.share_capability_secret_commitment ||
    blake3Base64Url(base64UrlDecode(shareSlug)) !== tokenHash ||
    blake3Base64Url(capabilitySecret) !== shareCapabilitySecretCommitment ||
    passwordCapabilitySecretCommitment !== resource.password_capability_secret_commitment ||
    (passwordProtected &&
      (!passwordCapabilitySecret ||
        blake3Base64Url(passwordCapabilitySecret) !== passwordCapabilitySecretCommitment)) ||
    (!passwordProtected && passwordCapabilitySecretValue !== "none")
  ) {
    throw new Error("share_link_secret_backup_plaintext_invalid");
  }

  installManagedShareSecretsFromBackup(
    state,
    shareSlug,
    capabilitySecret,
    passwordCapabilitySecret,
  );

  return `/share/${shareSlug}#cap=${shareCapabilitySecret}&wpb=${workspacePinBootstrapHash}`;
}

function requireStringField(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("share_link_secret_backup_plaintext_invalid");
  }
  return value;
}

export function handleOpenInitialAkeUmkDelivery(state: WorkerKeyState, p: HandlerPayload): unknown {
  const initialAke = decodeInitialAkeRecord<InitialAkeArtifact>(p.initialAke);
  const initialKeyDelivery = decodeInitialAkeRecord<InitialKeyDeliveryRecord>(p.initialKeyDelivery);
  const responderState = state.initialAkeResponderSessions.get(initialAke.transcript_hash);
  if (!responderState) throw new Error("initial_ake_responder_session_missing");
  let umk: Uint8Array;
  try {
    umk = openInitialAkeUmkDelivery({
      initialAke,
      initialKeyDelivery,
      responderState,
      senderSigningPublicKeyMaterial:
        p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    });
  } finally {
    responderState.secret.fill(0);
    state.initialAkeResponderSessions.delete(initialAke.transcript_hash);
  }
  state.umk = umk;
  return { status: "ok" };
}

export function handleOpenInitialAkeKekDelivery(state: WorkerKeyState, p: HandlerPayload): unknown {
  const initialAke = decodeInitialAkeRecord<InitialAkeArtifact>(p.initialAke);
  const initialKeyDelivery = decodeInitialAkeRecord<InitialKeyDeliveryRecord>(p.initialKeyDelivery);
  const metadata = initialKeyDelivery.metadata as Record<string, unknown>;
  const responderState = state.initialAkeResponderSessions.get(initialAke.transcript_hash);
  if (!responderState) throw new Error("initial_ake_responder_session_missing");
  let kek: Uint8Array;
  try {
    kek = openInitialAkeUmkDelivery({
      initialAke,
      initialKeyDelivery,
      responderState,
      senderSigningPublicKeyMaterial:
        p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    });
  } finally {
    responderState.secret.fill(0);
    state.initialAkeResponderSessions.delete(initialAke.transcript_hash);
  }
  setCachedKek(state, metadata.workspace_id as string, kek, metadata.key_version as number);
  return { status: "ok" };
}

export function handleOpenInitialAkeDeviceStateTransferDelivery(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const initialAke = decodeInitialAkeRecord<InitialAkeArtifact>(p.initialAke);
  const initialKeyDelivery = decodeInitialAkeRecord<InitialKeyDeliveryRecord>(p.initialKeyDelivery);
  const responderState = state.initialAkeResponderSessions.get(initialAke.transcript_hash);
  if (!responderState) throw new Error("initial_ake_responder_session_missing");
  let plaintext: Uint8Array;
  try {
    plaintext = openInitialAkeUmkDelivery({
      initialAke,
      initialKeyDelivery,
      responderState,
      senderSigningPublicKeyMaterial:
        p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    });
  } finally {
    responderState.secret.fill(0);
    state.initialAkeResponderSessions.delete(initialAke.transcript_hash);
  }
  return parseJsonStrictBytes(plaintext);
}

function initialAkePrekeyStateKey(purpose: string, operationId: string, prekeyId: string): string {
  return `${purpose}:${operationId}:${prekeyId}`;
}

function initialAkePrekeyStateKeyFromTranscript(
  initialAke: InitialAkeArtifact | InitialAkeOffer,
): string {
  const transcript = initialAke.transcript as Record<string, unknown>;
  const context = transcript.context as Record<string, unknown>;
  const responder = transcript.responder as Record<string, unknown>;
  return initialAkePrekeyStateKey(
    initialAke.purpose,
    context.operation_id as string,
    responder.prekey_id as string,
  );
}

export function handleWrapKekForInvitationBootstrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const bootstrapSecret = p.bootstrapSecret as string | undefined;
  const protocol = assertInvitationBootstrapProtocol(p.protocol);
  const aad = assertRecord(p.aad, "invitation_bootstrap_aad_invalid");
  const plaintext = assertRecord(p.plaintext, "invitation_bootstrap_plaintext_invalid");
  assertInvitationBootstrapAad(aad, protocol, workspaceId);
  const redeemAuthorityInvitationId = p.redeemAuthorityInvitationId as string | undefined;
  const workspaceScope =
    protocol === workspaceInvitationBootstrapProtocol || aad.scope_kind === "workspace";
  const includeWorkspaceKek = workspaceScope && p.includeWorkspaceKek !== false;
  const packageKey = randomBytes(32);
  const aadBytes = invitationPackageAad(aad);
  const payloadNonce = randomBytes(24);
  const payload = { ...plaintext };
  let maintenanceWrap: Record<string, unknown> | undefined;

  if (redeemAuthorityInvitationId) {
    const privateMaterial = state.invitationRedeemAuthorities.get(redeemAuthorityInvitationId);
    if (!privateMaterial) throw new Error("invitation_redeem_authority_missing");
    if (
      privateMaterial.owner_kind !== "invitation_redeem_authority" ||
      privateMaterial.owner_id !== redeemAuthorityInvitationId
    ) {
      throw new Error("invitation_redeem_authority_owner_mismatch");
    }
    payload.redeem_authority_private_key_material = privateMaterial as unknown as StrictJsonValue;
  }

  if (includeWorkspaceKek) {
    const { kek } = requireKekForWorkspace(state, workspaceId, keyVersion);
    payload.workspace_kek = base64UrlEncode(kek);
    maintenanceWrap = wrapInvitationBootstrapPackageKey(kek, keyVersion, aadBytes, packageKey);
  } else if (workspaceScope) {
    if (aad.delivery_mode !== "known_recipient" || !p.recipientDelivery) {
      throw new Error("invitation_bootstrap_workspace_kek_required");
    }
    const { kek } = requireKekForWorkspace(state, workspaceId, keyVersion);
    maintenanceWrap = wrapInvitationBootstrapPackageKey(kek, keyVersion, aadBytes, packageKey);
  } else {
    const maintenanceShareSlug = assertString(
      p.maintenanceShareSlug,
      "invitation_bootstrap_maintenance_share_required",
    );
    const maintenanceShareKey = state.shareSecrets.get(maintenanceShareSlug)?.dekEncryptionKey;
    if (!maintenanceShareKey || maintenanceShareKey.length !== 32) {
      throw new Error("invitation_bootstrap_maintenance_key_required");
    }
    if (aad.delivery_mode === "unknown_fragment") {
      payload.guest_share_key = base64UrlEncode(maintenanceShareKey);
    }
    assertInvitationBootstrapMaintenanceContext(protocol, aad, keyVersion, {
      key_version: keyVersion,
      nonce: base64UrlEncode(new Uint8Array(24)),
      ciphertext: base64UrlEncode(new Uint8Array(48)),
    });
    maintenanceWrap = wrapInvitationBootstrapPackageKey(
      maintenanceShareKey,
      keyVersion,
      aadBytes,
      packageKey,
    );
  }

  assertInvitationBootstrapPlaintext(payload, {
    protocol,
    workspaceId,
    keyVersion,
    aad,
  });

  const recipientWrap = buildInvitationRecipientWrap(state, p, {
    protocol,
    workspaceId,
    keyVersion,
    aad,
    aadBytes,
    packageKey,
    bootstrapSecret,
  });

  return {
    protocol,
    version: 1,
    suite_id: invitationBootstrapSuite,
    workspace_id: workspaceId,
    key_version: keyVersion,
    aad,
    encrypted_payload: {
      nonce: base64UrlEncode(payloadNonce),
      ciphertext: base64UrlEncode(
        xchacha20poly1305(packageKey, payloadNonce, aadBytes).encrypt(
          canonicalizeStrictBytes(payload as StrictJsonValue),
        ),
      ),
    },
    package_key_recipient_wrap: recipientWrap,
    package_key_maintenance_wrap: maintenanceWrap,
  };
}

function buildInvitationRecipientWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
  context: {
    protocol: string;
    workspaceId: string;
    keyVersion: number;
    aad: Record<string, unknown>;
    aadBytes: Uint8Array;
    packageKey: Uint8Array;
    bootstrapSecret?: string;
  },
): Record<string, unknown> {
  const delivery = p.recipientDelivery as Record<string, unknown> | undefined;
  if (!delivery) {
    if (!context.bootstrapSecret) throw new Error("invitation_bootstrap_secret_invalid");
    const key = deriveInvitationBootstrapRecipientKey(context.bootstrapSecret);
    const nonce = randomBytes(24);
    return {
      nonce: base64UrlEncode(nonce),
      ciphertext: base64UrlEncode(
        xchacha20poly1305(key, nonce, context.aadBytes).encrypt(context.packageKey),
      ),
    };
  }

  const recipientUserId = assertString(
    delivery.recipientUserId,
    "invitation_recipient_user_invalid",
  );
  if (
    context.aad.delivery_mode !== "known_recipient" ||
    context.aad.recipient_user_id !== recipientUserId
  ) {
    throw new Error("invitation_recipient_binding_invalid");
  }
  const senderSigningPrivateKeyMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const senderSigningPublicKeyMaterial = publicKeyMaterialFromPrivate(
    senderSigningPrivateKeyMaterial,
  );
  return {
    delivery_mode: "known_recipient",
    recipient_user_id: recipientUserId,
    sender_signing_public_key_material: senderSigningPublicKeyMaterial,
    wraps: [],
  };
}

function wrapInvitationBootstrapPackageKey(
  maintenanceKey: Uint8Array,
  keyVersion: number,
  aadBytes: Uint8Array,
  packageKey: Uint8Array,
): Record<string, unknown> {
  const maintenanceNonce = randomBytes(24);
  const maintenanceCipher = xchacha20poly1305(maintenanceKey, maintenanceNonce, aadBytes);
  return {
    key_version: keyVersion,
    nonce: base64UrlEncode(maintenanceNonce),
    ciphertext: base64UrlEncode(maintenanceCipher.encrypt(packageKey)),
  };
}

export function handleUnwrapKekFromInvitationBootstrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const bootstrap = assertRecord(p.bootstrap, "invitation_bootstrap_package_invalid");
  const bootstrapSecret = p.bootstrapSecret as string | undefined;
  const { protocol, workspaceId, keyVersion, aad, encryptedPayload, recipientWrap } =
    assertInvitationBootstrapPackage(bootstrap);

  const aadBytes = invitationPackageAad(aad);
  if (recipientWrap.delivery_mode === "known_recipient") {
    throw new Error("invitation_recipient_bound_delivery_required");
  }
  const packageKey = openUnknownInvitationRecipientWrap(bootstrapSecret, aadBytes, recipientWrap);
  if (packageKey.length !== 32) throw new Error("invitation_bootstrap_package_key_invalid");
  const plaintext = parseJsonStrictBytes(
    xchacha20poly1305(
      packageKey,
      base64UrlDecode(encryptedPayload.nonce as string),
      aadBytes,
    ).decrypt(base64UrlDecode(encryptedPayload.ciphertext as string)),
  ) as Record<string, unknown>;
  const { sanitizedPlaintext, encodedKek, encodedGuestShareKey, redeemAuthority } =
    assertInvitationBootstrapPlaintext(plaintext, {
      protocol,
      workspaceId,
      keyVersion,
      aad,
    });

  if (encodedKek) {
    const kek = base64UrlDecode(encodedKek);
    if (kek.length !== 32) throw new Error("invitation_bootstrap_kek_invalid");
    setCachedKek(state, workspaceId, kek, keyVersion);
    setActiveKekVersion(state, workspaceId, keyVersion);
  }
  if (encodedGuestShareKey) {
    const shareKey = base64UrlDecode(encodedGuestShareKey);
    if (shareKey.length !== 32) throw new Error("invitation_bootstrap_share_key_invalid");
    const invitationId = assertString(
      sanitizedPlaintext.guest_invitation_id,
      "guest_invitation_bootstrap_id_invalid",
    );
    state.pendingGuestInvitationShareKeys.get(invitationId)?.fill(0);
    state.pendingGuestInvitationShareKeys.set(invitationId, new Uint8Array(shareKey));
    shareKey.fill(0);
  }
  state.invitationRedeemAuthorities.set(redeemAuthority.ownerId, redeemAuthority.privateMaterial);
  return {
    ...sanitizedPlaintext,
    redeem_authority_signing_key_id: redeemAuthority.signingKeyId,
    redeem_authority_hybrid_signing_public_key_material: redeemAuthority.publicMaterial,
  };
}

function openUnknownInvitationRecipientWrap(
  bootstrapSecret: string | undefined,
  aadBytes: Uint8Array,
  recipientWrap: Record<string, unknown>,
): Uint8Array {
  if (!bootstrapSecret) throw new Error("invitation_bootstrap_secret_invalid");
  const key = deriveInvitationBootstrapRecipientKey(bootstrapSecret);
  return xchacha20poly1305(key, base64UrlDecode(recipientWrap.nonce as string), aadBytes).decrypt(
    base64UrlDecode(recipientWrap.ciphertext as string),
  );
}

export function handleCacheKek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const kek = p.kek as Uint8Array;
  const keyVersion = p.keyVersion as number;
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

export async function handleStoreKekForOffline(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const { kek } = requireKekForWorkspace(state, workspaceId, keyVersion);

  const wrapped = await dskEncrypt(dsk, kek, buildOfflineKekCacheAad(workspaceId, keyVersion));
  await storeDskStoreValueInWorker(offlineKekKey(workspaceId), {
    ...wrapped,
    keyVersion,
    cachedAt: Date.now(),
  } satisfies OfflineKekStoredEntry);
  await addOfflineKekIndex(workspaceId);
  return { stored: true };
}

export async function handleRestoreKekFromOffline(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const workspaceId = p.workspaceId as string;
  const isActive = (p.isActive as boolean | undefined) ?? true;
  const entry = await loadDskStoreValueStrictInWorker<OfflineKekStoredEntry>(
    offlineKekKey(workspaceId),
  );
  if (!entry) return { restored: false };
  const keyVersion = (p.keyVersion as number | undefined) ?? entry.keyVersion;
  if (entry.keyVersion !== keyVersion) throw new Error("offline_kek_key_version_mismatch");

  const kek = await dskDecrypt(
    dsk,
    entry.ciphertext,
    entry.iv,
    buildOfflineKekCacheAad(workspaceId, keyVersion),
  );
  setCachedKek(state, workspaceId, kek, keyVersion);
  if (isActive) {
    setActiveKekVersion(state, workspaceId, keyVersion);
  }
  return { restored: true, keyVersion, cachedAt: entry.cachedAt };
}

export async function handleLoadOfflineKekMetadata(p: HandlerPayload): Promise<unknown> {
  const workspaceId = p.workspaceId as string;
  const entry = await loadDskStoreValueStrictInWorker<OfflineKekStoredEntry>(
    offlineKekKey(workspaceId),
  );
  if (!entry) return { metadata: null };
  return {
    metadata: {
      workspaceId,
      keyVersion: entry.keyVersion,
      cachedAt: entry.cachedAt,
    },
  };
}

export async function handleDeleteKekForOffline(p: HandlerPayload): Promise<unknown> {
  const workspaceId = p.workspaceId as string;
  await deleteDskStoreValueInWorker(offlineKekKey(workspaceId));
  await removeOfflineKekIndex(workspaceId);
  return {};
}

export async function handleDeleteOrphanedKeksForOffline(p: HandlerPayload): Promise<unknown> {
  const activeWorkspaceIds = Array.isArray(p.activeWorkspaceIds) ? p.activeWorkspaceIds : [];
  const active = new Set(
    activeWorkspaceIds.filter((value): value is string => typeof value === "string"),
  );
  const index = await loadOfflineKekIndex();
  const remaining: string[] = [];
  await Promise.all(
    index.map(async (workspaceId) => {
      if (active.has(workspaceId)) {
        remaining.push(workspaceId);
      } else {
        await deleteDskStoreValueInWorker(offlineKekKey(workspaceId));
      }
    }),
  );
  await storeDskStoreValueInWorker(OFFLINE_KEK_INDEX_KEY, remaining);
  return {};
}

function offlineKekKey(workspaceId: string): string {
  return `${OFFLINE_KEK_KEY_PREFIX}${workspaceId}`;
}

async function loadOfflineKekIndex(): Promise<string[]> {
  const index = await loadDskStoreValueInWorker<string[]>(OFFLINE_KEK_INDEX_KEY);
  return Array.isArray(index)
    ? index.filter((value): value is string => typeof value === "string")
    : [];
}

async function addOfflineKekIndex(workspaceId: string): Promise<void> {
  const index = await loadOfflineKekIndex();
  if (!index.includes(workspaceId)) {
    await storeDskStoreValueInWorker(OFFLINE_KEK_INDEX_KEY, [...index, workspaceId]);
  }
}

async function removeOfflineKekIndex(workspaceId: string): Promise<void> {
  const index = await loadOfflineKekIndex();
  await storeDskStoreValueInWorker(
    OFFLINE_KEK_INDEX_KEY,
    index.filter((entry) => entry !== workspaceId),
  );
}
