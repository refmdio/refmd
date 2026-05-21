import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { WorkerKeyState } from "../state";
import { getCachedKek, setActiveKekVersion, setCachedKek } from "../state";
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
  createInitialAkeUmkDelivery,
  createInitialAkeKekDelivery,
  createInitialAkeDeviceStateTransferDelivery,
  decodeInitialAkeRecord,
  generateInitialAkeResponderPrekey,
  openInitialAkeUmkDelivery,
  type InitialAkeArtifact,
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
  storeDskStoreValueInWorker,
} from "./dsk-idb";

const invitationBootstrapSuite = "refmd-v2-invitation-bootstrap-xchacha20poly1305";
const workspaceInvitationBootstrapProtocol = "refmd.workspace-invitation-bootstrap";
const guestInvitationBootstrapProtocol = "refmd.guest-invitation-bootstrap";
const hkdfZeroSalt = new Uint8Array(32);
const OFFLINE_KEK_KEY_PREFIX = "refmd-offline-key:kek:";
const OFFLINE_KEK_INDEX_KEY = "refmd-offline-key:kek-index";

type OfflineKekStoredEntry = {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
  keyVersion: number;
  cachedAt: number;
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
    return;
  }

  assertExactKeys(
    aad,
    [
      "guest_invitation_id",
      "key_version_context",
      "permission",
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
  const recipientWrap = assertInvitationCiphertext(
    bootstrap.package_key_recipient_wrap,
    "invitation_bootstrap_recipient_wrap_invalid",
  );
  const maintenanceWrap = assertInvitationMaintenanceWrap(bootstrap.package_key_maintenance_wrap);
  assertInvitationBootstrapMaintenanceContext(protocol, aad, keyVersion, maintenanceWrap);
  return { protocol, workspaceId, keyVersion, aad, encryptedPayload, recipientWrap };
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
        "workspace_kek",
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
    const encodedKek = assertString(plaintext.workspace_kek, "invitation_bootstrap_kek_invalid");
    const redeemAuthority = validateInvitationRedeemAuthority(
      plaintext.redeem_authority_private_key_material,
      plaintext.invitation_id as string,
    );
    return {
      sanitizedPlaintext: sanitizedInvitationBootstrapPlaintext(plaintext),
      encodedKek,
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
      ...(workspaceScope ? ["workspace_kek"] : []),
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
  const encodedKek = workspaceScope
    ? assertString(plaintext.workspace_kek, "invitation_bootstrap_kek_invalid")
    : null;
  const redeemAuthority = validateInvitationRedeemAuthority(
    plaintext.redeem_authority_private_key_material,
    plaintext.guest_invitation_id as string,
  );
  return {
    sanitizedPlaintext: sanitizedInvitationBootstrapPlaintext(plaintext),
    encodedKek,
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
      ([key]) => key !== "workspace_kek" && key !== "redeem_authority_private_key_material",
    ),
  );
}

export function handleGenerateKek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = (p.keyVersion as number) ?? 1;
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
    case "share_participant_bootstrap_wrap":
    case "share_link_secret_backup_wrap":
    case "workspace_invitation_kek_wrap":
    case "guest_invitation_workspace_kek_wrap":
    case "guest_invitation_share_key_wrap":
      return value;
    default:
      throw new Error("signed_pq_wrap_purpose_invalid");
  }
}

export function handleGenerateInitialAkeResponderPrekey(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const result = generateInitialAkeResponderPrekey({
    purpose:
      p.purpose === "device_approval_kek_initial" || p.purpose === "trust_transfer"
        ? p.purpose
        : "umk_distribution",
    operationId: p.operationId as string,
    userId: p.userId as string,
    deviceId: p.deviceId as string,
    serverChallenge: p.serverChallenge as string | undefined,
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

function positiveInteger(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error(code);
  }
  return value;
}

export function handleCreateInitialAkeUmkDelivery(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const senderEncryptionKeyId = currentDeviceEncryptionKeyId(state);
  return createInitialAkeUmkDelivery({
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
}

export function handleCreateInitialAkeKekDelivery(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const { kek } = requireKekForWorkspace(state, workspaceId, keyVersion);
  const senderEncryptionKeyId = currentDeviceEncryptionKeyId(state);
  return createInitialAkeKekDelivery({
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
}

export function handleCreateInitialAkeDeviceStateTransferDelivery(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const senderEncryptionKeyId = currentDeviceEncryptionKeyId(state);
  return createInitialAkeDeviceStateTransferDelivery({
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
}

function currentDeviceEncryptionKeyId(state: WorkerKeyState): string {
  const publicMaterial =
    state.deviceHybridEncryptionPublicKeyMaterial ??
    publicHybridEncryptionMaterialFromPrivate(
      requireDeviceHybridEncryptionPrivateKeyMaterial(state),
    );
  return computeHybridEncryptionKeyId(publicMaterial);
}

export function handleOpenSignedPqDeviceKekWrap(state: WorkerKeyState, p: HandlerPayload): unknown {
  const record = signedPqWrapRecordFromEnvelope(p.record);
  const senderSigningPublicKeyMaterial =
    p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial;
  const kek = openSignedPqWrap({
    record,
    senderSigningPublicKeyMaterial,
    recipientPrivateKeyMaterial: requireDeviceHybridEncryptionPrivateKeyMaterial(state),
    expectedOperationCheckpoint: p.expectedOperationCheckpoint as {
      sequence: number;
      checkpointHash: string;
    },
  });
  const resource = record.resource as Record<string, unknown>;
  setCachedKek(state, resource.workspace_id as string, kek, resource.kek_version as number);
  return { status: "ok" };
}

export function handleOpenSignedPqMemberKekWrap(state: WorkerKeyState, p: HandlerPayload): unknown {
  const record = signedPqWrapRecordFromEnvelope(p.record);
  const senderSigningPublicKeyMaterial =
    p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial;
  const kek = openSignedPqWrap({
    record,
    senderSigningPublicKeyMaterial,
    recipientPrivateKeyMaterial: requireIdentityHybridEncryptionPrivateKeyMaterial(state),
    expectedOperationCheckpoint: p.expectedOperationCheckpoint as {
      sequence: number;
      checkpointHash: string;
    },
  });
  const resource = record.resource as Record<string, unknown>;
  setCachedKek(state, resource.workspace_id as string, kek, resource.kek_version as number);
  return { status: "ok" };
}

export function handleOpenSignedPqShareLinkSecretBackupWrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const record = signedPqWrapRecordFromEnvelope(p.record);
  if (record.purpose !== "share_link_secret_backup_wrap") {
    throw new Error("signed_pq_wrap_purpose_invalid");
  }
  const plaintext = openSignedPqWrap({
    record,
    senderSigningPublicKeyMaterial:
      p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    recipientPrivateKeyMaterial: requireDeviceHybridEncryptionPrivateKeyMaterial(state),
    expectedOperationCheckpoint: p.expectedOperationCheckpoint as {
      sequence: number;
      checkpointHash: string;
    },
  });
  return {
    sharePathWithFragment: shareLinkSecretBackupPathWithFragment(
      record,
      plaintext,
      p.expectedShareId,
    ),
  };
}

function shareLinkSecretBackupPathWithFragment(
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

  if (
    decoded.protocol !== "refmd.share-link-secret-backup-plaintext" ||
    decoded.version !== 1 ||
    shareId !== expectedShareId ||
    shareId !== resource.share_id ||
    tokenHash !== resource.token_hash ||
    workspacePinBootstrapHash !== resource.workspace_pin_bootstrap_hash ||
    shareCapabilitySecretCommitment !== resource.share_capability_secret_commitment ||
    blake3Base64Url(base64UrlDecode(shareSlug)) !== tokenHash ||
    blake3Base64Url(base64UrlDecode(shareCapabilitySecret)) !== shareCapabilitySecretCommitment
  ) {
    throw new Error("share_link_secret_backup_plaintext_invalid");
  }

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
  const prekeyStateKey = initialAkePrekeyStateKeyFromTranscript(initialAke);
  const privatePrekey = state.initialAkeResponderPrekeys.get(prekeyStateKey);
  if (!privatePrekey) throw new Error("initial_ake_responder_prekey_missing");
  let umk: Uint8Array;
  try {
    umk = openInitialAkeUmkDelivery({
      initialAke,
      initialKeyDelivery,
      privatePrekey,
      senderSigningPublicKeyMaterial:
        p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    });
  } finally {
    state.initialAkeResponderPrekeys.delete(prekeyStateKey);
  }
  state.umk = umk;
  return { status: "ok" };
}

export function handleOpenInitialAkeKekDelivery(state: WorkerKeyState, p: HandlerPayload): unknown {
  const initialAke = decodeInitialAkeRecord<InitialAkeArtifact>(p.initialAke);
  const initialKeyDelivery = decodeInitialAkeRecord<InitialKeyDeliveryRecord>(p.initialKeyDelivery);
  const metadata = initialKeyDelivery.metadata as Record<string, unknown>;
  const prekeyStateKey = initialAkePrekeyStateKeyFromTranscript(initialAke);
  const privatePrekey = state.initialAkeResponderPrekeys.get(prekeyStateKey);
  if (!privatePrekey) throw new Error("initial_ake_responder_prekey_missing");
  let kek: Uint8Array;
  try {
    kek = openInitialAkeUmkDelivery({
      initialAke,
      initialKeyDelivery,
      privatePrekey,
      senderSigningPublicKeyMaterial:
        p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    });
  } finally {
    state.initialAkeResponderPrekeys.delete(prekeyStateKey);
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
  const prekeyStateKey = initialAkePrekeyStateKeyFromTranscript(initialAke);
  const privatePrekey = state.initialAkeResponderPrekeys.get(prekeyStateKey);
  if (!privatePrekey) throw new Error("initial_ake_responder_prekey_missing");
  let plaintext: Uint8Array;
  try {
    plaintext = openInitialAkeUmkDelivery({
      initialAke,
      initialKeyDelivery,
      privatePrekey,
      senderSigningPublicKeyMaterial:
        p.senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
    });
  } finally {
    state.initialAkeResponderPrekeys.delete(prekeyStateKey);
  }
  return parseJsonStrictBytes(plaintext);
}

function initialAkePrekeyStateKey(purpose: string, operationId: string, prekeyId: string): string {
  return `${purpose}:${operationId}:${prekeyId}`;
}

function initialAkePrekeyStateKeyFromTranscript(initialAke: InitialAkeArtifact): string {
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
  const bootstrapSecret = p.bootstrapSecret as string;
  const protocol = assertInvitationBootstrapProtocol(p.protocol);
  const aad = assertRecord(p.aad, "invitation_bootstrap_aad_invalid");
  const plaintext = assertRecord(p.plaintext, "invitation_bootstrap_plaintext_invalid");
  assertInvitationBootstrapAad(aad, protocol, workspaceId);
  const redeemAuthorityInvitationId = p.redeemAuthorityInvitationId as string | undefined;
  const workspaceScope =
    protocol === workspaceInvitationBootstrapProtocol || aad.scope_kind === "workspace";
  const includeWorkspaceKek = workspaceScope && p.includeWorkspaceKek !== false;
  const key = deriveInvitationBootstrapRecipientKey(bootstrapSecret);
  const packageKey = randomBytes(32);
  const aadBytes = invitationPackageAad(aad);
  const recipientNonce = randomBytes(24);
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
    throw new Error("invitation_bootstrap_workspace_kek_required");
  } else {
    const maintenanceWrapKey = p.maintenanceWrapKey;
    if (!(maintenanceWrapKey instanceof Uint8Array) || maintenanceWrapKey.length !== 32) {
      throw new Error("invitation_bootstrap_maintenance_key_required");
    }
    assertInvitationBootstrapMaintenanceContext(protocol, aad, keyVersion, {
      key_version: keyVersion,
      nonce: base64UrlEncode(new Uint8Array(24)),
      ciphertext: base64UrlEncode(new Uint8Array(48)),
    });
    maintenanceWrap = wrapInvitationBootstrapPackageKey(
      maintenanceWrapKey,
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
    package_key_recipient_wrap: {
      nonce: base64UrlEncode(recipientNonce),
      ciphertext: base64UrlEncode(
        xchacha20poly1305(key, recipientNonce, aadBytes).encrypt(packageKey),
      ),
    },
    package_key_maintenance_wrap: maintenanceWrap,
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
  const bootstrapSecret = p.bootstrapSecret as string;
  const { protocol, workspaceId, keyVersion, aad, encryptedPayload, recipientWrap } =
    assertInvitationBootstrapPackage(bootstrap);

  const key = deriveInvitationBootstrapRecipientKey(bootstrapSecret);
  const aadBytes = invitationPackageAad(aad);
  const packageKey = xchacha20poly1305(
    key,
    base64UrlDecode(recipientWrap.nonce as string),
    aadBytes,
  ).decrypt(base64UrlDecode(recipientWrap.ciphertext as string));
  if (packageKey.length !== 32) throw new Error("invitation_bootstrap_package_key_invalid");
  const plaintext = parseJsonStrictBytes(
    xchacha20poly1305(
      packageKey,
      base64UrlDecode(encryptedPayload.nonce as string),
      aadBytes,
    ).decrypt(base64UrlDecode(encryptedPayload.ciphertext as string)),
  ) as Record<string, unknown>;
  const { sanitizedPlaintext, encodedKek, redeemAuthority } = assertInvitationBootstrapPlaintext(
    plaintext,
    {
      protocol,
      workspaceId,
      keyVersion,
      aad,
    },
  );

  if (encodedKek) {
    const kek = base64UrlDecode(encodedKek);
    if (kek.length !== 32) throw new Error("invitation_bootstrap_kek_invalid");
    setCachedKek(state, workspaceId, kek, keyVersion);
    setActiveKekVersion(state, workspaceId, keyVersion);
  }
  state.invitationRedeemAuthorities.set(redeemAuthority.ownerId, redeemAuthority.privateMaterial);
  return {
    ...sanitizedPlaintext,
    redeem_authority_signing_key_id: redeemAuthority.signingKeyId,
    redeem_authority_hybrid_signing_public_key_material: redeemAuthority.publicMaterial,
  };
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
  const entry = await loadDskStoreValueInWorker<OfflineKekStoredEntry>(offlineKekKey(workspaceId));
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
  const entry = await loadDskStoreValueInWorker<OfflineKekStoredEntry>(offlineKekKey(workspaceId));
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
