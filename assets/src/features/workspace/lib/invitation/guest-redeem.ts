import { authState, deviceState, setCryptoWorkerReady, setFullSession } from "@/entities/session";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { ApiError, authApi, workspacesApi, type components } from "@/shared/api";
import { persistCurrentKeysWithDsk, persistDeviceId } from "@/shared/lib/auth/key-persistence";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { persistGuestAuthBootstrap } from "./guest-auth-bootstrap";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { buildRecoverableIdentitySecretRecord } from "@/shared/lib/crypto/recoverable-identity-secret-record";
import { verifyRecipientBoundAuthorizationSignature } from "@/shared/lib/crypto/signature";
import { buildRecipientBoundAuthorizationTranscript } from "@/shared/lib/crypto/signature-key-directory-transcripts";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  pinInitialKeyDirectoryCheckpoint,
  rememberVerifiedKeyDirectoryLineageDurably,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { verifyWorkspaceSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";
import { buildGuestInvitationRedeemedKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/invitation-events";
import { buildInitialUserKeyDirectoryBootstrap } from "@/shared/lib/crypto/key-directory/initial";
import { getCryptoWorker, type CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";
import {
  getScopedCryptoWorker,
  terminateScopedCryptoWorker,
} from "@/shared/lib/crypto/worker/scoped";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import {
  readActiveGuestRedeemMaterial,
  readGuestRedeemMaterial,
  forgetGuestRedeemMaterial,
  rememberGuestRedeemMaterial,
  type GuestRedeemMaterial,
} from "./guest-material";
import {
  invitationBootstrapSecret,
  invitationLookupToken,
  invitationSecretCommitment,
} from "./token";
import {
  assertGuestInvitationBootstrapPlaintext,
  pinWorkspaceCheckpointFromBootstrap,
  type GuestInvitationBootstrapPlaintext,
} from "./bootstrap";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import type { SignedPqWrapRecord } from "@/shared/lib/crypto/signed-pq-wrap";
import {
  assertWorkspacePinBootstrapEnvelope,
  verifyAndInstallWorkspacePinBootstrap,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import {
  consumeLocalDeliveryAttempt,
  getApprovedGuestDeliveryAttempt,
  InvitationDeliveryPendingError,
  type DeliveryAttempt,
} from "./delivery-attempt";
import { persistRedeemedGuestWorkspaceKek } from "./guest-workspace-kek";
import {
  assertRecipientDeliveryAdmissionBindings,
  recipientDeliveryOperationProof,
  verifyRecipientDeliveryAdmission,
} from "@/shared/lib/anti-rollback/key-directory-pin/recipient-delivery-admission";

type RedeemResponse = components["schemas"]["RedeemGuestInvitationResponse"];
export type GuestRedeemResult = RedeemResponse;
type MeResponse = Awaited<ReturnType<typeof authApi.me>>;
type GuestRedeemBody = Omit<
  components["schemas"]["RedeemGuestInvitationRequest"],
  "token" | "workspace_key_directory_checkpoint" | "workspace_key_directory_events"
>;
type GuestInvitationLookupResult = Omit<
  components["schemas"]["InvitationLookupResponse"],
  "kind" | "workspace_id" | "scope_kind" | "scope_id" | "share_id" | "permission"
> & {
  kind: "guest";
  workspace_id: string;
  scope_kind: "workspace" | "document" | "folder" | "share";
  scope_id: string;
  share_id: string | null;
  permission: "view" | "edit";
  key_version_context: GuestKeyVersionContext;
};

interface GuestKeyVersionContext {
  workspace_kek_version: number | "NOT_APPLICABLE";
  share_key_version: number | "NOT_APPLICABLE";
  dek_version: number | "NOT_APPLICABLE";
}

interface KnownGuestCompletionSteps {
  restoreWorker: () => Promise<MeResponse>;
  restoreShareKey: () => Promise<void>;
  persistAuthBootstrap: (me: MeResponse) => Promise<void>;
  pinUserKeyDirectory: () => Promise<void>;
  establishSession: (me: MeResponse) => void;
  rememberRedeemMaterial: () => Promise<void>;
  deletePendingKeys: () => Promise<void>;
}

export async function completeKnownGuestRedemption(
  steps: KnownGuestCompletionSteps,
): Promise<void> {
  const me = await steps.restoreWorker();
  await steps.restoreShareKey();
  await steps.persistAuthBootstrap(me);
  await steps.pinUserKeyDirectory();
  steps.establishSession(me);
  await steps.rememberRedeemMaterial();
  await steps.deletePendingKeys();
}

function guestPackageKeyVersion(lookup: GuestInvitationLookupResult): number {
  const context = lookup.key_version_context;
  const version =
    lookup.scope_kind === "workspace" ? context.workspace_kek_version : context.share_key_version;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
    throw new Error("Guest invitation key version context is malformed.");
  }
  return version;
}

function guestWorkspaceKekVersion(context: GuestKeyVersionContext): number {
  const version = context.workspace_kek_version;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
    throw new Error("Guest invitation workspace key version is malformed.");
  }
  return version;
}

function guestShareVersion(value: number | "NOT_APPLICABLE", code: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) throw new Error(code);
  return value;
}

function guestShareMetadata(response: RedeemResponse) {
  if (
    !response.share_id ||
    (response.share_scope_kind !== "document" && response.share_scope_kind !== "folder") ||
    !response.share_scope_id
  ) {
    throw new Error("Guest invitation share scope is malformed.");
  }
  return {
    shareId: response.share_id,
    scopeKind: response.share_scope_kind,
    scopeId: response.share_scope_id,
    permission: response.permission,
    shareKeyVersion: guestShareVersion(
      response.key_version_context.share_key_version,
      "Guest invitation share key version is malformed.",
    ),
    dekVersion: guestShareVersion(
      response.key_version_context.dek_version,
      "Guest invitation DEK version is malformed.",
    ),
  } as const;
}

async function restoreGuestShareKeyForResponse(
  worker: ReturnType<typeof getCryptoWorker>,
  response: RedeemResponse,
): Promise<void> {
  if (response.scope_kind === "workspace") return;
  const restored = await worker.restoreGuestInvitationShareKey(guestShareMetadata(response));
  if (!restored.restored) throw new Error("Guest invitation share key is unavailable.");
}

function findGuestInvitationCreatedEvent(
  events: Record<string, unknown>[],
  invitationId: string,
): Record<string, unknown> {
  const event = events.find((envelope) => {
    const payload = envelope.payload as Record<string, unknown> | undefined;
    const body = payload?.body as Record<string, unknown> | undefined;
    return (
      payload?.event_type === "guest_invitation_created" &&
      body?.guest_invitation_id === invitationId
    );
  });
  if (!event) throw new Error("guest_invitation_created_event_missing");
  return event;
}

async function assertGuestInvitationBootstrapMatchesCreatedEvent(params: {
  lookupToken: string;
  bootstrapSecret: string | null;
  bootstrapPackage: Record<string, unknown>;
  plaintext: GuestInvitationBootstrapPlaintext;
  createdEvents: Record<string, unknown>[];
  shareId: string | null;
}): Promise<void> {
  const event = findGuestInvitationCreatedEvent(
    params.createdEvents,
    params.plaintext.guest_invitation_id,
  );
  const payload = event.payload as Record<string, unknown> | undefined;
  const body = payload?.body as Record<string, unknown> | undefined;
  const redeemAuthority = body?.redeem_authority as Record<string, unknown> | undefined;
  const aad = params.bootstrapPackage.aad as Record<string, unknown> | undefined;
  const delivery = guestInvitationDeliveryBinding(params.bootstrapPackage);
  const allowedShareIds =
    params.plaintext.scope_kind === "workspace" ? [] : [stringField(params.shareId)];
  const expectedAllowedShareIdsHash = blake3Base64Url(
    canonicalizeStrictBytes({ allowed_share_ids: allowedShareIds } as StrictJsonValue),
  );
  const bodyKeyContext = body?.key_version_context as Record<string, unknown> | undefined;
  const expectedCapabilityContextHash = blake3Base64Url(
    canonicalizeStrictBytes({
      guest_invitation_id: params.plaintext.guest_invitation_id,
      permission: params.plaintext.permission,
      scope_id: params.plaintext.scope_id,
      scope_kind: params.plaintext.scope_kind,
      workspace_id: params.plaintext.workspace_id,
    } as StrictJsonValue),
  );
  if (
    body?.workspace_id !== params.plaintext.workspace_id ||
    body.guest_invitation_id !== params.plaintext.guest_invitation_id ||
    body.scope_kind !== params.plaintext.scope_kind ||
    body.scope_id !== params.plaintext.scope_id ||
    body.permission !== params.plaintext.permission ||
    body.allowed_share_ids_hash !== expectedAllowedShareIdsHash ||
    bodyKeyContext?.workspace_kek_version !==
      params.plaintext.key_version_context.workspace_kek_version ||
    bodyKeyContext?.share_key_version !== params.plaintext.key_version_context.share_key_version ||
    bodyKeyContext?.dek_version !== params.plaintext.key_version_context.dek_version ||
    (delivery.deliveryMode === "unknown_fragment" &&
      (!params.bootstrapSecret ||
        body.bootstrap_key_commitment !==
          (await invitationSecretCommitment(
            params.lookupToken,
            params.bootstrapSecret,
            "guest",
          )))) ||
    body.delivery_mode !== delivery.deliveryMode ||
    body.recipient_user_id !== recipientTranscriptValue(delivery.recipientUserId) ||
    !sameStrings(body.recipient_device_ids, delivery.recipientDeviceIds) ||
    aad?.delivery_mode !== delivery.deliveryMode ||
    aad.recipient_user_id !== recipientTranscriptValue(delivery.recipientUserId) ||
    !sameStrings(aad.recipient_device_ids, delivery.recipientDeviceIds) ||
    body.bootstrap_package_hash !==
      blake3Base64Url(canonicalizeStrictBytes(params.bootstrapPackage as StrictJsonValue)) ||
    body.bootstrap_suite_id !== "refmd-v2-invitation-bootstrap-xchacha20poly1305" ||
    body.capability_context_hash !== expectedCapabilityContextHash ||
    redeemAuthority?.signing_key_id !== params.plaintext.redeem_authority_signing_key_id
  ) {
    throw new Error("guest_invitation_bootstrap_created_event_mismatch");
  }
}

function guestInvitationDeliveryBinding(bootstrapPackage: Record<string, unknown>): {
  deliveryMode: "unknown_fragment" | "known_recipient";
  recipientUserId: string | null;
  recipientDeviceIds: string[];
} {
  const recipientWrap = bootstrapPackage.package_key_recipient_wrap as
    | Record<string, unknown>
    | undefined;
  if (recipientWrap?.delivery_mode !== "known_recipient") {
    return {
      deliveryMode: "unknown_fragment",
      recipientUserId: null,
      recipientDeviceIds: [],
    };
  }
  if (typeof recipientWrap.recipient_user_id !== "string" || !Array.isArray(recipientWrap.wraps)) {
    throw new Error("guest_invitation_recipient_binding_invalid");
  }
  const records = recipientWrap.wraps as Record<string, unknown>[];
  if (records.length === 0) throw new Error("guest_invitation_recipient_binding_invalid");
  const recipientDeviceIds = records.map((record) => {
    const resource = record.resource as Record<string, unknown> | undefined;
    return stringField(resource?.recipient_device_id);
  });
  return {
    deliveryMode: "known_recipient",
    recipientUserId: recipientWrap.recipient_user_id,
    recipientDeviceIds,
  };
}

function sameStrings(value: unknown, expected: string[]): boolean {
  return (
    Array.isArray(value) &&
    value.every((entry) => typeof entry === "string") &&
    [...value].sort().join("\u0000") === [...expected].sort().join("\u0000")
  );
}

function recipientTranscriptValue(value: string | null): string {
  return value ?? "NOT_APPLICABLE";
}

async function ensureDskInWorker(worker: CryptoWorkerClient = getCryptoWorker()): Promise<void> {
  if (await worker.loadStoredDsk()) {
    return;
  }

  await worker.generateDsk();
}

async function createGuestRedeemMaterial(
  guestUserId: string,
  worker: CryptoWorkerClient = getCryptoWorker(),
): Promise<GuestRedeemMaterial> {
  const deviceId = crypto.randomUUID();
  await worker.setUserContext(guestUserId, deviceId);
  await worker.generateUmk();
  const identityPublic = await worker.generateIdentityKeys();
  const encryptedIdentity = await worker.wrapIdentityKeysForServer(guestUserId, 1);
  const devicePublic = await worker.generateDeviceKeys({ deviceId });
  const clientNonce = await worker.generateClientNonce();
  const recoverableIdentitySecretRecord = buildRecoverableIdentitySecretRecord({
    id: crypto.randomUUID(),
    userId: guestUserId,
    identityKeyEpoch: 1,
    previousRecordHash: "GENESIS",
    encryptedSigningPrivateMaterial: encryptedIdentity.encryptedHybridSigningPrivateKeyMaterial,
    signingPrivateMaterialNonce: encryptedIdentity.hybridSigningPrivateKeyMaterialNonce,
    encryptedEncryptionPrivateMaterial:
      encryptedIdentity.encryptedHybridEncryptionPrivateKeyMaterial,
    encryptionPrivateMaterialNonce: encryptedIdentity.hybridEncryptionPrivateKeyMaterialNonce,
    signingKeyId: encryptedIdentity.signingKeyId,
    encryptionKeyId: encryptedIdentity.encryptionKeyId,
    isCurrent: true,
  });
  const identityHybridSigningPublicKeyMaterial = identityPublic.hybridSigningPublicKeyMaterial;
  const deviceHybridSigningPublicKeyMaterial = devicePublic.hybridSigningPublicKeyMaterial;
  const userKeyDirectory = await buildInitialUserKeyDirectoryBootstrap({
    userId: guestUserId,
    deviceId,
    identityHybridSigningPublicKeyMaterial,
    identityHybridEncryptionPublicKeyMaterial: identityPublic.hybridEncryptionPublicKeyMaterial,
    deviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial: devicePublic.hybridEncryptionPublicKeyMaterial,
    worker,
  });

  const body: GuestRedeemBody = {
    guest_user_id: guestUserId,
    device_id: deviceId,
    device_hybrid_encryption_public_key_material: devicePublic.hybridEncryptionPublicKeyMaterial,
    device_hybrid_signing_public_key_material: devicePublic.hybridSigningPublicKeyMaterial,
    identity_hybrid_encryption_public_key_material:
      identityPublic.hybridEncryptionPublicKeyMaterial,
    identity_hybrid_signing_public_key_material: identityPublic.hybridSigningPublicKeyMaterial,
    recoverable_identity_secret_record: recoverableIdentitySecretRecord,
    client_nonce: base64UrlEncode(clientNonce),
    device_name: getDeviceName(),
    device_type: getDeviceType(),
    user_key_directory_events: userKeyDirectory.userEvents,
    user_key_directory_checkpoint: userKeyDirectory.userCheckpoint,
  };

  return {
    body,
    publicKeys: {
      identityHybridSigningPublicKeyMaterial,
      identityEcdhPublic: base64UrlEncode(identityPublic.ecdhPublic),
      deviceSigningKeyId: devicePublic.signingKeyId,
      deviceEncryptionKeyId: devicePublic.encryptionKeyId,
      deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic: base64UrlEncode(devicePublic.ecdhPublic),
    },
  };
}

function guestTargetRegistration(
  material: GuestRedeemMaterial,
): components["schemas"]["InvitationDeliveryTargetRegistration"] {
  const identityEncryption = material.body.identity_hybrid_encryption_public_key_material;
  const identitySigning = material.body.identity_hybrid_signing_public_key_material;
  const deviceEncryption = material.body.device_hybrid_encryption_public_key_material;
  const deviceSigning = material.body.device_hybrid_signing_public_key_material;
  const recoverableIdentitySecretRecord = material.body.recoverable_identity_secret_record;
  if (
    !identityEncryption ||
    !identitySigning ||
    !deviceEncryption ||
    !deviceSigning ||
    !recoverableIdentitySecretRecord
  ) {
    throw new Error("Guest invitation registration keys are incomplete.");
  }
  return {
    identity_hybrid_encryption_public_key_material: identityEncryption,
    identity_hybrid_signing_public_key_material: identitySigning,
    device_hybrid_encryption_public_key_material: deviceEncryption,
    device_hybrid_signing_public_key_material: deviceSigning,
    recoverable_identity_secret_record: recoverableIdentitySecretRecord,
    user_key_directory_events: material.body.user_key_directory_events,
    user_key_directory_checkpoint: material.body.user_key_directory_checkpoint,
  };
}

interface PreparedGuestInvitationBootstrap {
  lookup: GuestInvitationLookupResult;
  delivery: ReturnType<typeof guestInvitationDeliveryBinding>;
  bootstrapPlaintext: GuestInvitationBootstrapPlaintext;
  baseCheckpoint: KeyDirectoryEnvelope;
  workspaceKeyDirectoryEventAncestry: KeyDirectoryEnvelope[];
}

async function prepareGuestInvitationBootstrap(
  token: string,
  lookupOverride?: GuestInvitationLookupResult,
): Promise<PreparedGuestInvitationBootstrap> {
  const lookupToken = invitationLookupToken(token);
  const bootstrapSecret = invitationBootstrapSecret(token);
  const lookup =
    lookupOverride ??
    ((await workspacesApi.lookupInvitation(lookupToken)) as GuestInvitationLookupResult);
  if (lookup.kind !== "guest" || !lookup.encrypted_bootstrap_package) {
    throw new Error("This guest invitation is missing workspace trust state.");
  }
  const delivery = guestInvitationDeliveryBinding(lookup.encrypted_bootstrap_package);
  if (delivery.deliveryMode === "unknown_fragment" && !bootstrapSecret) {
    throw new Error("This invitation link is missing guest key material.");
  }
  if (delivery.deliveryMode === "known_recipient") {
    const auth = authState();
    const device = deviceState();
    if (
      !auth ||
      auth.user.accountType === "guest" ||
      auth.user.id !== delivery.recipientUserId ||
      !device ||
      !delivery.recipientDeviceIds.includes(device.deviceId)
    ) {
      throw new Error("This guest invitation belongs to another account or device.");
    }
  }
  const bootstrapPlaintext = assertGuestInvitationBootstrapPlaintext(
    await getCryptoWorker().unwrapKekFromInvitationBootstrap({
      bootstrap: lookup.encrypted_bootstrap_package,
      ...(bootstrapSecret ? { bootstrapSecret } : {}),
    }),
  );
  if (
    bootstrapPlaintext.workspace_id !== lookup.workspace_id ||
    bootstrapPlaintext.guest_invitation_id !== lookup.invitation_id ||
    bootstrapPlaintext.scope_kind !== lookup.scope_kind ||
    bootstrapPlaintext.scope_id !== lookup.scope_id ||
    bootstrapPlaintext.permission !== lookup.permission ||
    lookup.encrypted_bootstrap_package.workspace_id !== lookup.workspace_id ||
    lookup.encrypted_bootstrap_package.key_version !== guestPackageKeyVersion(lookup) ||
    !lookup.workspace_key_directory_checkpoint
  ) {
    throw new Error("Guest invitation key material is malformed.");
  }
  const workspaceKeyDirectoryCheckpoint = assertKeyDirectoryEnvelope(
    lookup.workspace_key_directory_checkpoint,
    "guest_invitation_workspace_key_directory_checkpoint_invalid",
  );
  const workspaceKeyDirectoryCheckpointAncestry =
    lookup.workspace_key_directory_checkpoint_ancestry.map((entry) =>
      assertKeyDirectoryEnvelope(entry, "guest_invitation_workspace_checkpoint_ancestry_invalid"),
    );
  const workspaceKeyDirectoryEventAncestry = lookup.workspace_key_directory_event_ancestry.map(
    (entry) =>
      assertKeyDirectoryEnvelope(entry, "guest_invitation_workspace_event_ancestry_invalid"),
  );
  await assertGuestInvitationBootstrapMatchesCreatedEvent({
    lookupToken,
    bootstrapSecret,
    bootstrapPackage: lookup.encrypted_bootstrap_package,
    plaintext: bootstrapPlaintext,
    createdEvents: workspaceKeyDirectoryEventAncestry,
    shareId: lookup.share_id,
  });
  const existingWorkspacePin = await getKeyDirectoryPin("workspace", lookup.workspace_id);
  const bootstrapCheckpoint = operationCheckpointFromEnvelope(
    bootstrapPlaintext.workspace_key_directory_checkpoint,
  );
  const bootstrapAlreadyCovered =
    existingWorkspacePin &&
    (existingWorkspacePin.checkpointSequence > bootstrapCheckpoint.sequence ||
      (existingWorkspacePin.checkpointSequence === bootstrapCheckpoint.sequence &&
        existingWorkspacePin.checkpointHash === bootstrapCheckpoint.checkpointHash)) &&
    existingWorkspacePin.eventHeadSequence >= bootstrapCheckpoint.coveredHeadSequence;
  if (!bootstrapAlreadyCovered) {
    await pinWorkspaceCheckpointFromBootstrap({
      workspaceId: bootstrapPlaintext.workspace_id,
      checkpointEnvelope: bootstrapPlaintext.workspace_key_directory_checkpoint,
      workspaceKeyDirectoryEventAncestry,
      workspacePinBootstrapHash: bootstrapPlaintext.workspace_pin_bootstrap_hash,
      workspacePinBootstrap: bootstrapPlaintext.workspace_pin_bootstrap,
    });
  }
  const baseCheckpoint = await ensureWorkspaceCheckpointPinned({
    workspaceId: lookup.workspace_id,
    checkpointEnvelope: workspaceKeyDirectoryCheckpoint,
    checkpointAncestry: workspaceKeyDirectoryCheckpointAncestry,
    eventAncestry: workspaceKeyDirectoryEventAncestry,
  });
  return {
    lookup,
    delivery,
    bootstrapPlaintext,
    baseCheckpoint,
    workspaceKeyDirectoryEventAncestry,
  };
}

async function buildGuestRedeemAdmission(
  token: string,
  material: GuestRedeemMaterial,
  prepared?: PreparedGuestInvitationBootstrap,
): Promise<{
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
  bootstrapPlaintext: GuestInvitationBootstrapPlaintext;
  baseCheckpoint: KeyDirectoryEnvelope;
  workspaceKeyDirectoryEventAncestry: KeyDirectoryEnvelope[];
  deliveryMode: "unknown_fragment" | "known_recipient";
}> {
  const bootstrap = prepared ?? (await prepareGuestInvitationBootstrap(token));
  const {
    lookup,
    delivery,
    bootstrapPlaintext,
    baseCheckpoint,
    workspaceKeyDirectoryEventAncestry,
  } = bootstrap;
  const append = await buildGuestInvitationRedeemedKeyDirectoryAppend({
    workspaceId: lookup.workspace_id,
    checkpointEnvelope: baseCheckpoint,
    invitationId: lookup.invitation_id,
    guestGrantId: crypto.randomUUID(),
    redeemAuthoritySigningKeyId: bootstrapPlaintext.redeem_authority_signing_key_id,
    guestUserId: material.body.guest_user_id,
    guestDeviceId: material.body.device_id,
    guestIdentityHybridEncryptionPublicKeyMaterial: material.body
      .identity_hybrid_encryption_public_key_material as never,
    guestDeviceHybridSigningPublicKeyMaterial: material.body
      .device_hybrid_signing_public_key_material as never,
    guestDeviceHybridEncryptionPublicKeyMaterial: material.body
      .device_hybrid_encryption_public_key_material as never,
    guestEncryptionKeyId: material.publicKeys.deviceEncryptionKeyId,
    guestSigningKeyId: material.publicKeys.deviceSigningKeyId,
    scopeKind: lookup.scope_kind,
    scopeId: lookup.scope_id,
    permission: lookup.permission,
    recipientAccountUserId: delivery.recipientUserId,
    recipientAccountDeviceId:
      delivery.deliveryMode === "known_recipient" ? (deviceState()?.deviceId ?? null) : null,
  });
  return {
    workspace_key_directory_events: append.events,
    workspace_key_directory_checkpoint: append.checkpoint,
    bootstrapPlaintext,
    baseCheckpoint,
    workspaceKeyDirectoryEventAncestry: workspaceKeyDirectoryEventAncestry,
    deliveryMode: delivery.deliveryMode,
  };
}

async function ensureWorkspaceCheckpointPinned(params: {
  workspaceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  checkpointAncestry: KeyDirectoryEnvelope[];
  eventAncestry: KeyDirectoryEnvelope[];
}): Promise<KeyDirectoryEnvelope> {
  const pin = await getKeyDirectoryPin("workspace", params.workspaceId);
  const checkpointHash = hashKeyDirectoryCheckpointEnvelope(params.checkpointEnvelope);
  const operationCheckpoint = operationCheckpointFromEnvelope(params.checkpointEnvelope);
  if (
    pin &&
    pin.checkpointSequence === operationCheckpoint.sequence &&
    pin.checkpointHash === checkpointHash &&
    pin.eventHeadSequence === operationCheckpoint.coveredHeadSequence &&
    pin.eventHeadHash === operationCheckpoint.coveredHeadHash
  ) {
    await rememberVerifiedKeyDirectoryLineageDurably({
      scopeKind: "workspace",
      scopeId: params.workspaceId,
      checkpointEnvelope: params.checkpointEnvelope as unknown as SignedKeyDirectoryEnvelope,
      checkpointAncestry: params.checkpointAncestry as unknown as SignedKeyDirectoryEnvelope[],
      eventAncestry: params.eventAncestry as unknown as SignedKeyDirectoryEnvelope[],
    });
    return params.checkpointEnvelope;
  }

  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    checkpointEnvelope: params.checkpointEnvelope,
    checkpointAncestry: params.checkpointAncestry,
    eventAncestry: params.eventAncestry,
  });
  await rememberVerifiedKeyDirectoryLineageDurably({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    checkpointEnvelope: params.checkpointEnvelope as unknown as SignedKeyDirectoryEnvelope,
    checkpointAncestry: params.checkpointAncestry as unknown as SignedKeyDirectoryEnvelope[],
    eventAncestry: params.eventAncestry as unknown as SignedKeyDirectoryEnvelope[],
  });
  return params.checkpointEnvelope;
}

async function advanceWorkspacePinWithAcceptedAppend(params: {
  workspaceId: string;
  baseCheckpointEnvelope: KeyDirectoryEnvelope;
  acceptedCheckpointEnvelope: KeyDirectoryEnvelope;
  acceptedEventEnvelopes: KeyDirectoryEnvelope[];
  authorityEventAncestry: KeyDirectoryEnvelope[];
}): Promise<void> {
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    checkpointEnvelope: params.acceptedCheckpointEnvelope,
    checkpointAncestry: [params.baseCheckpointEnvelope],
    eventAncestry: params.acceptedEventEnvelopes,
    authorityEventAncestry: params.authorityEventAncestry,
  });
}

function operationCheckpointFromEnvelope(checkpointEnvelope: KeyDirectoryEnvelope) {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const covered = payload?.covered_event_head as Record<string, unknown> | undefined;
  if (!payload || !covered) throw new Error("key_directory_checkpoint_invalid");
  return {
    sequence: numberField(payload.sequence),
    checkpointHash: hashKeyDirectoryCheckpointEnvelope(checkpointEnvelope),
    coveredHeadSequence: numberField(covered.head_sequence),
    coveredHeadHash: stringField(covered.head_hash),
  };
}

function numberField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error("key_directory_number_invalid");
  }
  return value;
}

function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("key_directory_string_invalid");
  }
  return value;
}

async function restoreWorkerForGuestSession(
  response: RedeemResponse,
  material: GuestRedeemMaterial,
): Promise<MeResponse> {
  const [hasStoredDsk, me] = await Promise.all([getCryptoWorker().hasStoredDsk(), authApi.me()]);
  if (!hasStoredDsk) {
    throw new Error("Guest keys are not available on this device.");
  }

  await getCryptoWorker().init({
    dsk: null,
    useStoredDsk: true,
    userId: response.guest_user_id,
    deviceId: response.guest_device_id,
    deviceSigningKeyId: material.publicKeys.deviceSigningKeyId,
    keyRestoreEndpointRef: null,
  });
  await importGuestIdentityFromMaterial(getCryptoWorker(), material);

  const ready = await getCryptoWorker().isReady();
  if (!ready || material.body.guest_user_id !== response.guest_user_id) {
    throw new Error("Guest keys are not available on this device.");
  }
  return me;
}

function setGuestSession(
  response: RedeemResponse,
  material: GuestRedeemMaterial,
  me: MeResponse,
): void {
  setGuestIdentitySession(response.guest_user_id, response.guest_device_id, material, me);
  setCurrentWorkspaceId(response.workspace_id);
}

function setGuestIdentitySession(
  guestUserId: string,
  guestDeviceId: string,
  material: GuestRedeemMaterial,
  me: MeResponse,
  ready = true,
): void {
  setCryptoWorkerReady(ready);
  persistDeviceId(guestDeviceId, guestUserId);
  setFullSession(
    {
      user: { id: me.user_id, email: me.email, name: me.name, accountType: "guest" },
      sessionId: me.session_id,
      identityHybridSigningPublicKeyMaterial:
        material.publicKeys.identityHybridSigningPublicKeyMaterial,
      identityEcdhPublic: base64UrlDecode(material.publicKeys.identityEcdhPublic),
      expiresAt: me.expires_at,
    },
    {
      deviceId: guestDeviceId,
      deviceSigningKeyId: material.publicKeys.deviceSigningKeyId,
      deviceKeyCheckpointSequence: me.device_key_checkpoint_sequence ?? null,
      deviceKeyCheckpointHash: me.device_key_checkpoint_hash ?? null,
      deviceHybridSigningPublicKeyMaterial:
        material.publicKeys.deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic: base64UrlDecode(material.publicKeys.deviceEcdhPublic),
    },
  );
}

async function redeemGuestInvitationWithRebasedAdmission(
  token: string,
  lookupToken: string,
  material: GuestRedeemMaterial,
  prepared?: PreparedGuestInvitationBootstrap,
): Promise<{
  admission: Awaited<ReturnType<typeof buildGuestRedeemAdmission>>;
  response: RedeemResponse;
}> {
  let admission = await buildGuestRedeemAdmission(token, material, prepared);
  const submit = () => {
    const {
      bootstrapPlaintext: _bootstrapPlaintext,
      baseCheckpoint: _baseCheckpoint,
      workspaceKeyDirectoryEventAncestry: _workspaceKeyDirectoryEventAncestry,
      deliveryMode: _deliveryMode,
      ...redeemAdmission
    } = admission;
    const body = {
      token: lookupToken,
      ...material.body,
      ...redeemAdmission,
    };
    return admission.deliveryMode === "known_recipient"
      ? workspacesApi.redeemKnownGuestInvitation(body)
      : workspacesApi.redeemGuestInvitation(body);
  };

  try {
    return { admission, response: await submit() };
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 422 && err.code === "invalid_key_directory")) {
      throw err;
    }
    if (admission.deliveryMode === "known_recipient") throw err;
    admission = await buildGuestRedeemAdmission(token, material);
    return { admission, response: await submit() };
  }
}

interface KnownGuestDeliveryArtifacts {
  authorization: Record<string, unknown>;
  redeem_freshness_proof: Record<string, unknown>;
  workspace_pin_bootstrap: Record<string, unknown>;
  delivery_wrap: Record<string, unknown>;
  workspace_key_directory_events: Record<string, unknown>[];
  workspace_key_directory_intermediate_checkpoint: Record<string, unknown>;
  workspace_key_directory_checkpoint: Record<string, unknown>;
}

async function reenterKnownRecipientGuestInvitation(params: {
  token: string;
  lookup: GuestInvitationLookupResult;
  material: GuestRedeemMaterial;
}): Promise<GuestRedeemResult> {
  const { material } = params;
  await restorePendingGuestKeysForReentry(params.token, material);
  const stagedSession = await authApi.me();
  if (
    stagedSession.account_type !== "guest" ||
    stagedSession.user_id !== material.body.guest_user_id ||
    stagedSession.device_id !== material.body.device_id
  ) {
    throw new Error("Guest invitation session belongs to another account or device.");
  }
  setGuestIdentitySession(
    material.body.guest_user_id,
    material.body.device_id,
    material,
    stagedSession,
    false,
  );
  const response = await requestKnownGuestReentry(params);
  const checkpoint = assertKeyDirectoryEnvelope(
    response.workspace_key_directory_checkpoint,
    "guest_reentry_checkpoint_invalid",
  );
  await acceptGuestReentryCheckpoint({
    workspaceId: response.workspace_id,
    guestDeviceId: response.guest_device_id,
    responseCheckpoint: checkpoint,
  });
  const me = await restoreWorkerForGuestSession(response, material);
  await restoreGuestShareKeyForResponse(getCryptoWorker(), response);
  await persistGuestAuthBootstrap(getCryptoWorker(), {
    userId: response.guest_user_id,
    email: me.email,
    name: me.name,
    deviceId: response.guest_device_id,
    deviceSigningKeyId: material.publicKeys.deviceSigningKeyId,
  });
  await pinGuestUserKeyDirectory(response);
  setGuestSession(response, material, me);
  await rememberGuestRedeemMaterial(params.token, material);
  return response satisfies GuestRedeemResult;
}

function requestKnownGuestReentry(params: {
  token: string;
  lookup: GuestInvitationLookupResult;
  material: GuestRedeemMaterial;
}): Promise<RedeemResponse> {
  return workspacesApi.redeemKnownGuestInvitation({
    token: invitationLookupToken(params.token),
    ...params.material.body,
    workspace_key_directory_events: params.lookup
      .workspace_key_directory_event_ancestry as components["schemas"]["RedeemGuestInvitationRequest"]["workspace_key_directory_events"],
    workspace_key_directory_checkpoint: params.lookup
      .workspace_key_directory_checkpoint as components["schemas"]["RedeemGuestInvitationRequest"]["workspace_key_directory_checkpoint"],
  });
}

async function restorePendingGuestKeysForReentry(
  token: string,
  material: GuestRedeemMaterial,
): Promise<void> {
  const worker = getCryptoWorker();
  await worker.lock();
  await ensureDskInWorker(worker);
  await worker.setUserContext(material.body.guest_user_id, material.body.device_id);
  const restored = await worker.restoreGuestPendingKeysWithDsk({
    storageKey: invitationLookupToken(token),
    userId: material.body.guest_user_id,
    signingKeyId: material.publicKeys.deviceSigningKeyId,
  });
  if (restored.restored) {
    await importGuestIdentityFromMaterial(worker, material);
    await worker.setInitialized();
    await worker.persistCurrentKeysWithDsk(material.body.guest_user_id);
    return;
  }

  await worker.init({
    dsk: null,
    useStoredDsk: true,
    userId: material.body.guest_user_id,
    deviceId: material.body.device_id,
    deviceSigningKeyId: material.publicKeys.deviceSigningKeyId,
    keyRestoreEndpointRef: null,
  });
  await importGuestIdentityFromMaterial(worker, material);
  if (!(await worker.isReady())) {
    throw new Error("Guest invitation keys are not available on this device.");
  }
}

async function redeemKnownRecipientGuestInvitation(
  token: string,
  lookup: GuestInvitationLookupResult,
): Promise<GuestRedeemResult> {
  let material = (await readGuestRedeemMaterial(token)) ?? (await readCurrentGuestRedeemMaterial());
  const serverGuestSession = material ? await getKnownGuestServerSession(material) : null;
  if (serverGuestSession && material) {
    return reenterKnownRecipientGuestInvitation({ token, lookup, material });
  }
  const auth = authState();
  const accountDevice = deviceState();
  if (
    auth?.user.accountType === "guest" &&
    accountDevice &&
    material &&
    auth.user.id === material.body.guest_user_id &&
    accountDevice.deviceId === material.body.device_id
  ) {
    return reenterKnownRecipientGuestInvitation({ token, lookup, material });
  }
  if (
    !auth ||
    auth.user.accountType === "guest" ||
    !accountDevice ||
    lookup.recipient_user_id !== auth.user.id ||
    !lookup.recipient_device_ids.includes(accountDevice.deviceId)
  ) {
    throw new Error("This guest invitation belongs to another account or device.");
  }
  const lookupToken = invitationLookupToken(token);
  const scopedWorkerKey = `guest-invitation:${lookupToken}`;
  const guestWorker = getScopedCryptoWorker(scopedWorkerKey);
  let consumeRequestStarted = false;
  let consumeCompleted = false;
  try {
    if (material) {
      if (await guestWorker.isReady()) {
        if ((await guestWorker.getDeviceId()) !== material.body.device_id) {
          throw new Error("Guest invitation keys belong to another device.");
        }
      } else {
        await ensureDskInWorker(guestWorker);
        await guestWorker.setUserContext(material.body.guest_user_id, material.body.device_id);
        const restored = await guestWorker.restoreGuestPendingKeysWithDsk({
          storageKey: lookupToken,
          userId: material.body.guest_user_id,
          signingKeyId: material.publicKeys.deviceSigningKeyId,
        });
        if (!restored.restored) {
          throw new Error("Guest invitation keys are not available on this device.");
        }
        await guestWorker.setInitialized();
      }
    } else {
      await ensureDskInWorker(guestWorker);
      material = await createGuestRedeemMaterial(crypto.randomUUID(), guestWorker);
      await guestWorker.setInitialized();
      await guestWorker.persistGuestPendingKeysWithDsk({
        storageKey: lookupToken,
        userId: material.body.guest_user_id,
      });
      await rememberGuestRedeemMaterial(token, material);
    }

    const targetRegistration = guestTargetRegistration(material);
    const attempt = await getApprovedGuestDeliveryAttempt({
      token,
      lookup: lookup as components["schemas"]["InvitationLookupResponse"],
      auth,
      device: accountDevice,
      target: {
        userId: material.body.guest_user_id,
        deviceId: material.body.device_id,
        registration: targetRegistration,
        registrationProof: {
          client_nonce: material.body.client_nonce,
          device_name: material.body.device_name,
          device_type: material.body.device_type,
        },
      },
    });
    const artifacts = assertKnownGuestDeliveryArtifacts(attempt);
    const baseCheckpoint = assertKeyDirectoryEnvelope(
      lookup.workspace_key_directory_checkpoint,
      "guest_invitation_workspace_key_directory_checkpoint_invalid",
    );
    const authorityEventAncestry = lookup.workspace_key_directory_event_ancestry.map((entry) =>
      assertKeyDirectoryEnvelope(entry, "guest_invitation_workspace_event_invalid"),
    );
    await verifyKnownGuestAuthorization({
      attempt,
      artifacts,
      baseCheckpoint,
      authorityEventAncestry,
    });

    const intermediateCheckpoint = assertKeyDirectoryEnvelope(
      artifacts.workspace_key_directory_intermediate_checkpoint,
      "guest_invitation_intermediate_checkpoint_invalid",
    );
    const finalCheckpoint = assertKeyDirectoryEnvelope(
      artifacts.workspace_key_directory_checkpoint,
      "guest_invitation_final_checkpoint_invalid",
    );
    const events = artifacts.workspace_key_directory_events.map((entry) =>
      assertKeyDirectoryEnvelope(entry, "guest_invitation_delivery_event_invalid"),
    );
    const recipientDeliveryAdmissionProof = {
      attempt,
      authorization: artifacts.authorization,
      freshnessProof: artifacts.redeem_freshness_proof,
      baseCheckpoint,
      currentCheckpoint: finalCheckpoint,
      authorityEventAncestry,
      acceptedEventAncestry: events,
    };
    assertRecipientDeliveryAdmissionBindings(recipientDeliveryAdmissionProof);

    consumeRequestStarted = true;
    let response: RedeemResponse;
    try {
      response = await workspacesApi.consumeGuestInvitationDeliveryAttempt(
        attempt.redeem_attempt_id,
        {
          token: lookupToken,
        },
      );
    } catch (error) {
      if (error instanceof ApiError) throw error;
      const me = await authApi.me();
      if (me.account_type !== "guest") throw error;
      if (me.user_id !== material.body.guest_user_id || me.device_id !== material.body.device_id) {
        throw new Error("Guest invitation session belongs to another account or device.");
      }
      await restorePendingGuestKeysForReentry(token, material);
      setGuestIdentitySession(
        material.body.guest_user_id,
        material.body.device_id,
        material,
        me,
        false,
      );
      consumeCompleted = true;
      consumeLocalDeliveryAttempt(token);
      const recovered = await requestKnownGuestReentry({ token, lookup, material });
      response = {
        ...recovered,
        recipient_delivery_artifacts:
          artifacts as unknown as components["schemas"]["ApproveInvitationDeliveryAttemptRequest"],
      };
    }
    consumeCompleted = true;
    consumeLocalDeliveryAttempt(token);
    if (
      !response.recipient_delivery_artifacts ||
      hashValue(response.recipient_delivery_artifacts) !== hashValue(artifacts)
    ) {
      throw new Error("Guest invitation key delivery response is malformed.");
    }

    await advanceWorkspacePinWithAcceptedAppend({
      workspaceId: response.workspace_id,
      baseCheckpointEnvelope: baseCheckpoint,
      acceptedCheckpointEnvelope: intermediateCheckpoint,
      acceptedEventEnvelopes: events.slice(0, 2),
      authorityEventAncestry,
    });
    await advanceWorkspacePinWithAcceptedAppend({
      workspaceId: response.workspace_id,
      baseCheckpointEnvelope: intermediateCheckpoint,
      acceptedCheckpointEnvelope: finalCheckpoint,
      acceptedEventEnvelopes: events.slice(2),
      authorityEventAncestry: events.slice(0, 2),
    });

    const verifiedAdmission = await verifyRecipientDeliveryAdmission(
      recipientDeliveryAdmissionProof,
    );

    const authorization = artifacts.authorization;
    const deliveryWrap = artifacts.delivery_wrap as unknown as SignedPqWrapRecord;
    const operationProof = recipientDeliveryOperationProof(verifiedAdmission, {
      ...deliveryWrap,
      workspace_key_directory_checkpoint: finalCheckpoint,
      workspace_key_directory_checkpoint_ancestry: [baseCheckpoint, intermediateCheckpoint],
      workspace_key_directory_event_ancestry: events,
    });
    await verifyWorkspaceSignedPqWrapOperation(response.workspace_id, operationProof);
    const resource = deliveryWrap.resource as Record<string, unknown>;
    const commonResourceValid =
      resource.workspace_id === response.workspace_id &&
      resource.guest_invitation_id === attempt.context_id &&
      resource.guest_user_id === material.body.guest_user_id &&
      resource.guest_device_id === material.body.device_id &&
      resource.permission === lookup.permission;
    if (!commonResourceValid) {
      throw new Error("Guest invitation key delivery wrap is malformed.");
    }
    if (lookup.scope_kind === "workspace") {
      if (
        deliveryWrap.purpose !== "guest_invitation_workspace_kek_wrap" ||
        resource.scope_kind !== "workspace" ||
        resource.scope_id !== "none" ||
        resource.kek_version !== lookup.key_version_context.workspace_kek_version
      ) {
        throw new Error("Guest invitation workspace key delivery wrap is malformed.");
      }
      await guestWorker.openRecipientBoundInvitationDeviceKekWrap({
        operationProof,
        recipientDeliveryAdmissionProof,
        senderSigningPublicKeyMaterial: authorization.hybrid_signing_public_key_material as never,
      });
      await persistRedeemedGuestWorkspaceKek(guestWorker, {
        userId: response.guest_user_id,
        workspaceId: response.workspace_id,
        keyVersion: guestWorkspaceKekVersion(lookup.key_version_context),
      });
    } else {
      if (
        deliveryWrap.purpose !== "guest_invitation_share_key_wrap" ||
        !lookup.share_id ||
        resource.share_id !== lookup.share_id ||
        !["document", "folder"].includes(String(resource.scope_kind)) ||
        (lookup.scope_kind !== "share" &&
          (resource.scope_kind !== lookup.scope_kind || resource.scope_id !== lookup.scope_id)) ||
        resource.share_key_version !== lookup.key_version_context.share_key_version ||
        resource.dek_version !== lookup.key_version_context.dek_version
      ) {
        throw new Error("Guest invitation share key delivery wrap is malformed.");
      }
      await guestWorker.openSignedPqGuestInvitationShareKeyWrap({
        operationProof,
        recipientDeliveryAdmissionProof,
        senderSigningPublicKeyMaterial: authorization.hybrid_signing_public_key_material as never,
      });
      await guestWorker.persistCurrentKeysWithDsk(response.guest_user_id);
    }
    const redeemedMaterial = material;
    if (!redeemedMaterial) throw new Error("Guest invitation material is unavailable.");

    await completeKnownGuestRedemption({
      restoreWorker: () => restoreWorkerForGuestSession(response, redeemedMaterial),
      restoreShareKey: () => restoreGuestShareKeyForResponse(getCryptoWorker(), response),
      persistAuthBootstrap: (me) =>
        persistGuestAuthBootstrap(getCryptoWorker(), {
          userId: response.guest_user_id,
          email: me.email,
          name: me.name,
          deviceId: response.guest_device_id,
          deviceSigningKeyId: redeemedMaterial.publicKeys.deviceSigningKeyId,
        }),
      pinUserKeyDirectory: () => pinGuestUserKeyDirectory(response),
      establishSession: (me) => setGuestSession(response, redeemedMaterial, me),
      rememberRedeemMaterial: () => rememberGuestRedeemMaterial(token, redeemedMaterial),
      deletePendingKeys: () => guestWorker.deleteGuestPendingKeysWithDsk(lookupToken),
    });
    return response satisfies GuestRedeemResult;
  } catch (error) {
    if (!consumeRequestStarted && !(error instanceof InvitationDeliveryPendingError) && material) {
      consumeLocalDeliveryAttempt(token);
      await guestWorker.deleteGuestPendingKeysWithDsk(lookupToken);
      await forgetGuestRedeemMaterial(token, material);
    } else if (consumeRequestStarted && !consumeCompleted && material) {
      consumeLocalDeliveryAttempt(token);
      await guestWorker.deleteGuestPendingKeysWithDsk(lookupToken);
      await forgetGuestRedeemMaterial(token, material);
    }
    throw error;
  } finally {
    terminateScopedCryptoWorker(scopedWorkerKey);
  }
}

async function importGuestIdentityFromMaterial(
  worker: CryptoWorkerClient,
  material: GuestRedeemMaterial,
): Promise<void> {
  const secretRecord = material.body.recoverable_identity_secret_record;

  await worker.importIdentityKeys({
    encryptedHybridEncryptionPrivateKeyMaterial: base64UrlDecode(
      secretRecord.encrypted_identity_hybrid_encryption_private_key_material,
    ),
    hybridEncryptionPrivateKeyMaterialNonce: base64UrlDecode(
      secretRecord.identity_hybrid_encryption_private_key_material_nonce,
    ),
    encryptionKeyId: secretRecord.encryption_key_id,
    encryptedHybridSigningPrivateKeyMaterial: base64UrlDecode(
      secretRecord.encrypted_identity_hybrid_signing_private_key_material,
    ),
    hybridSigningPrivateKeyMaterialNonce: base64UrlDecode(
      secretRecord.identity_hybrid_signing_private_key_material_nonce,
    ),
    signingKeyId: secretRecord.signing_key_id,
    identityKeyEpoch: secretRecord.identity_key_epoch,
    rotationDueAt: null,
  });
}

async function getKnownGuestServerSession(
  material: GuestRedeemMaterial,
): Promise<MeResponse | null> {
  const me = await authApi.me();
  if (me.account_type !== "guest") return null;
  if (me.user_id !== material.body.guest_user_id || me.device_id !== material.body.device_id) {
    throw new Error("Guest invitation session belongs to another account or device.");
  }
  return me;
}

function assertKnownGuestDeliveryArtifacts(attempt: DeliveryAttempt): KnownGuestDeliveryArtifacts {
  const value = attempt.approved_artifacts as Record<string, unknown>;
  const required = [
    "authorization",
    "delivery_wrap",
    "redeem_freshness_proof",
    "workspace_key_directory_checkpoint",
    "workspace_key_directory_events",
    "workspace_key_directory_intermediate_checkpoint",
    "workspace_pin_bootstrap",
  ];
  if (
    !value ||
    Object.keys(value).sort().join("\u0000") !== required.sort().join("\u0000") ||
    !Array.isArray(value.workspace_key_directory_events)
  ) {
    throw new Error("Guest invitation key delivery artifacts are malformed.");
  }
  return value as unknown as KnownGuestDeliveryArtifacts;
}

async function verifyKnownGuestAuthorization(params: {
  attempt: DeliveryAttempt;
  artifacts: KnownGuestDeliveryArtifacts;
  baseCheckpoint: KeyDirectoryEnvelope;
  authorityEventAncestry: KeyDirectoryEnvelope[];
}): Promise<void> {
  const { attempt, artifacts, baseCheckpoint } = params;
  const authorization = artifacts.authorization;
  const payload = authorization.payload as Record<string, unknown>;
  const freshness = artifacts.redeem_freshness_proof;
  const checkpointPayload = baseCheckpoint.payload as Record<string, unknown>;
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown>;
  if (
    payload?.protocol !== "refmd.recipient-bound-authorization" ||
    payload.redeem_attempt_id !== attempt.redeem_attempt_id ||
    payload.context_kind !== "guest_invitation" ||
    payload.context_id !== attempt.context_id ||
    payload.resource_hash !== attempt.resource_hash ||
    payload.recipient_redeem_nonce !== attempt.recipient_redeem_nonce ||
    payload.recipient_nonce_state_hash !== attempt.recipient_nonce_state_hash ||
    payload.live_redeem_challenge_hash !== attempt.live_redeem_challenge_hash ||
    payload.redeem_freshness_proof_hash !== hashValue(freshness) ||
    payload.current_checkpoint_sequence !== checkpointPayload.sequence ||
    payload.current_checkpoint_hash !== hashKeyDirectoryCheckpointEnvelope(baseCheckpoint) ||
    payload.current_event_head_sequence !== coveredHead.head_sequence ||
    payload.current_event_head_hash !== coveredHead.head_hash
  ) {
    throw new Error("Guest invitation key delivery authorization is malformed.");
  }
  const publicMaterial = authorization.hybrid_signing_public_key_material as never;
  const signingKeyId = stringField(authorization.signing_key_id);
  const freshnessDevice = freshness.authoritative_device as Record<string, unknown>;
  const transcript = buildRecipientBoundAuthorizationTranscript({
    ownerId: stringField((publicMaterial as Record<string, unknown>).owner_id),
    actorUserId: stringField(freshnessDevice.user_id),
    actorDeviceId: stringField(freshnessDevice.device_id),
    signingKeyId,
    authorizationPayload: payload,
  });
  if (
    hashValue(transcript) !== hashValue(authorization.transcript) ||
    !verifyRecipientBoundAuthorizationSignature({
      transcript,
      signature: authorization.signature as never,
      publicKeyMaterial: publicMaterial,
    })
  ) {
    throw new Error("Guest invitation authorization signature is invalid.");
  }
  await verifyAndInstallWorkspacePinBootstrap({
    workspaceId: attempt.workspace_id,
    authenticatedWorkspacePinBootstrapHash: stringField(payload.workspace_pin_bootstrap_hash),
    bootstrap: assertWorkspacePinBootstrapEnvelope(
      artifacts.workspace_pin_bootstrap,
      "workspace_pin_bootstrap_invalid",
    ),
    checkpointEnvelope: baseCheckpoint,
    workspaceKeyDirectoryEventAncestry: params.authorityEventAncestry,
    operationSequence: numberField(payload.not_after_event_sequence),
  });
}

function hashValue(value: unknown): string {
  return blake3Base64Url(canonicalizeStrictBytes(value as StrictJsonValue));
}

export async function redeemGuestInvitation(token: string) {
  const worker = getCryptoWorker();
  const bootstrapSecret = invitationBootstrapSecret(token);
  const lookupToken = invitationLookupToken(token);
  const lookup = (await workspacesApi.lookupInvitation(lookupToken)) as GuestInvitationLookupResult;
  if (lookup.kind !== "guest" || !lookup.encrypted_bootstrap_package) {
    throw new Error("This guest invitation is missing workspace trust state.");
  }
  if (lookup.delivery_mode === "known_recipient") {
    return redeemKnownRecipientGuestInvitation(token, lookup);
  }
  if (!bootstrapSecret) throw new Error("This invitation link is missing guest key material.");
  await worker.lock();
  await ensureDskInWorker();
  const storedMaterial =
    (await readGuestRedeemMaterial(token)) ?? (await readCurrentGuestRedeemMaterial());
  if (storedMaterial) {
    await worker.init({
      dsk: null,
      useStoredDsk: true,
      userId: storedMaterial.body.guest_user_id,
      deviceId: storedMaterial.body.device_id,
      deviceSigningKeyId: storedMaterial.publicKeys.deviceSigningKeyId,
      keyRestoreEndpointRef: null,
    });
    if (!(await worker.isReady())) {
      throw new Error("Guest keys are not available on this device.");
    }
  }
  const prepared = await prepareGuestInvitationBootstrap(token, lookup);

  if (storedMaterial) {
    const { admission, response } = await redeemGuestInvitationWithRebasedAdmission(
      token,
      lookupToken,
      storedMaterial,
      prepared,
    );
    const me = await restoreWorkerForGuestSession(response, storedMaterial);
    await restoreGuestShareKeyForResponse(worker, response);
    await persistGuestAuthBootstrap(worker, {
      userId: response.guest_user_id,
      email: me.email,
      name: me.name,
      deviceId: response.guest_device_id,
      deviceSigningKeyId: storedMaterial.publicKeys.deviceSigningKeyId,
    });
    await acceptGuestRedeemCheckpoint({
      response,
      admission,
      existingGuestDeviceId: response.guest_device_id,
      allowReentryCheckpoint: true,
    });
    await pinGuestUserKeyDirectory(response);
    setGuestSession(response, storedMaterial, me);
    await rememberGuestRedeemMaterial(token, storedMaterial);
    return response satisfies GuestRedeemResult;
  }
  const auth = authState();
  if (auth?.user.accountType === "guest") {
    throw new Error("Guest access is not available on this device.");
  }

  const material = await createGuestRedeemMaterial(crypto.randomUUID());
  const { admission, response } = await redeemGuestInvitationWithRebasedAdmission(
    token,
    lookupToken,
    material,
    prepared,
  );

  await worker.setUserContext(response.guest_user_id, response.guest_device_id);
  if (response.scope_kind === "workspace") {
    await persistRedeemedGuestWorkspaceKek(worker, {
      userId: response.guest_user_id,
      workspaceId: response.workspace_id,
      keyVersion: guestWorkspaceKekVersion(response.key_version_context),
    });
  } else {
    await worker.commitGuestInvitationShareKey({
      invitationId: response.invitation_id,
      ...guestShareMetadata(response),
    });
    await persistCurrentKeysWithDsk(response.guest_user_id);
  }

  await worker.setInitialized();
  await acceptGuestRedeemCheckpoint({
    response,
    admission,
    existingGuestDeviceId: response.guest_device_id,
    allowReentryCheckpoint: false,
  });
  const persistentMaterial: GuestRedeemMaterial = material;
  await rememberGuestRedeemMaterial(token, persistentMaterial);
  const me = await authApi.me();
  await persistGuestAuthBootstrap(worker, {
    userId: response.guest_user_id,
    email: me.email,
    name: me.name,
    deviceId: response.guest_device_id,
    deviceSigningKeyId: persistentMaterial.publicKeys.deviceSigningKeyId,
  });
  await pinGuestUserKeyDirectory(response);
  setGuestSession(response, persistentMaterial, me);

  return response satisfies GuestRedeemResult;
}

async function pinGuestUserKeyDirectory(response: RedeemResponse): Promise<void> {
  const checkpoint = assertKeyDirectoryEnvelope(
    response.user_key_directory_checkpoint,
    "guest_user_key_directory_checkpoint_invalid",
  );
  const events = response.user_key_directory_events.map((entry) =>
    assertKeyDirectoryEnvelope(entry, "guest_user_key_directory_event_invalid"),
  );
  const existing = await getKeyDirectoryPin("user", response.guest_user_id);
  if (!existing) {
    await pinInitialKeyDirectoryCheckpoint({
      scopeKind: "user",
      scopeId: response.guest_user_id,
      eventEnvelopes: events,
      checkpointEnvelope: checkpoint,
    });
    return;
  }

  const received = operationCheckpointFromEnvelope(checkpoint);
  if (
    existing.checkpointSequence !== received.sequence ||
    existing.checkpointHash !== received.checkpointHash ||
    existing.eventHeadSequence !== received.coveredHeadSequence ||
    existing.eventHeadHash !== received.coveredHeadHash
  ) {
    throw new Error("guest_user_key_directory_pin_mismatch");
  }
}

async function acceptGuestRedeemCheckpoint(params: {
  response: RedeemResponse;
  admission: Awaited<ReturnType<typeof buildGuestRedeemAdmission>>;
  existingGuestDeviceId: string;
  allowReentryCheckpoint: boolean;
}): Promise<void> {
  const responseCheckpoint = params.response.workspace_key_directory_checkpoint;
  if (!responseCheckpoint) {
    throw new Error("Guest invitation acceptance is missing workspace trust state.");
  }
  const responseKeyDirectoryCheckpoint = assertKeyDirectoryEnvelope(
    responseCheckpoint,
    "guest_response_key_directory_checkpoint_invalid",
  );
  const submittedHash = hashKeyDirectoryCheckpointEnvelope(
    params.admission.workspace_key_directory_checkpoint,
  );
  const responseHash = hashKeyDirectoryCheckpointEnvelope(responseKeyDirectoryCheckpoint);
  if (responseHash === submittedHash) {
    await advanceWorkspacePinWithAcceptedAppend({
      workspaceId: params.response.workspace_id,
      baseCheckpointEnvelope: params.admission.baseCheckpoint,
      acceptedCheckpointEnvelope: params.admission.workspace_key_directory_checkpoint,
      acceptedEventEnvelopes: params.admission.workspace_key_directory_events,
      authorityEventAncestry: params.admission.workspaceKeyDirectoryEventAncestry,
    });
    return;
  }

  if (!params.allowReentryCheckpoint) {
    throw new Error("Guest invitation trust state does not match the submitted append.");
  }

  await acceptGuestReentryCheckpoint({
    workspaceId: params.response.workspace_id,
    guestDeviceId: params.existingGuestDeviceId,
    responseCheckpoint: responseKeyDirectoryCheckpoint,
  });
}

async function acceptGuestReentryCheckpoint(params: {
  workspaceId: string;
  guestDeviceId: string;
  responseCheckpoint: KeyDirectoryEnvelope;
}): Promise<void> {
  const responseHash = hashKeyDirectoryCheckpointEnvelope(params.responseCheckpoint);
  const pin = await getKeyDirectoryPin("workspace", params.workspaceId);
  if (pin?.checkpointHash === responseHash) return;

  await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    rrpDeviceId: params.guestDeviceId,
    popWorker: getCryptoWorker(),
  });
  const updated = await getKeyDirectoryPin("workspace", params.workspaceId);
  const responseState = operationCheckpointFromEnvelope(params.responseCheckpoint);
  if (!updated || updated.checkpointSequence < responseState.sequence) {
    throw new Error("Guest invitation trust state does not match the accepted reentry checkpoint.");
  }
}

async function readCurrentGuestRedeemMaterial(): Promise<GuestRedeemMaterial | null> {
  const auth = authState();
  const device = deviceState();
  if (auth?.user.accountType !== "guest" || !device?.deviceId) return null;
  return readActiveGuestRedeemMaterial(auth.user.id, device.deviceId);
}
