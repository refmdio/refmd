import { ApiError, workspacesApi } from "@/shared/api";
import type { components } from "@/shared/api/schema";
import type { AuthState, DeviceState } from "@/entities/session";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { verifyWorkspaceSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";
import { buildWorkspaceInvitationRedeemedKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/invitation-events";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  rememberVerifiedKeyDirectoryLineageDurably,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { persistWorkspaceKekForDevice } from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { type SignedPqWrapRecord } from "@/shared/lib/crypto/signed-pq-wrap";
import { buildRecipientBoundAuthorizationTranscript } from "@/shared/lib/crypto/signature-key-directory-transcripts";
import { verifyRecipientBoundAuthorizationSignature } from "@/shared/lib/crypto/signature";
import { putOfflineKek } from "@/shared/lib/offline/storage/store";
import {
  assertWorkspacePinBootstrapEnvelope,
  verifyAndInstallWorkspacePinBootstrap,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import {
  invitationBootstrapSecret,
  invitationLookupToken,
  invitationSecretCommitment,
} from "./token";
import {
  assertWorkspaceInvitationBootstrapPlaintext,
  pinWorkspaceCheckpointFromBootstrap,
  type WorkspaceInvitationBootstrapPlaintext,
} from "./bootstrap";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import {
  consumeLocalDeliveryAttempt,
  getApprovedWorkspaceDeliveryAttempt,
  type DeliveryAttempt,
} from "./delivery-attempt";
import { recoverWorkspaceInvitationMemberEnvelope } from "./member-envelope-recovery";
import {
  assertRecipientDeliveryAdmissionBindings,
  recipientDeliveryOperationProof,
  verifyRecipientDeliveryAdmission,
} from "@/shared/lib/anti-rollback/key-directory-pin/recipient-delivery-admission";
const MEMBER_ENVELOPE_MAX_RETRIES = 20;
const MEMBER_ENVELOPE_RETRY_DELAY_MS = 1_000;
type AcceptInvitationMemberEnvelope =
  components["schemas"]["AcceptInvitationRequest"]["member_envelope"];
interface InvitationAcceptResult {
  status?: "accepted";
  workspace_id: string;
  workspace_name: string;
  invitation_id: string;
  kek_version: number;
  role_name?: string | null;
  encrypted_bootstrap_package?: Record<string, unknown> | null;
  workspace_key_directory_checkpoint?: KeyDirectoryEnvelope | null;
  recipient_delivery_artifacts?: Record<string, unknown> | null;
}
type InvitationLookupResult = components["schemas"]["InvitationLookupResponse"];
interface KekSaveState {
  deviceSaved: boolean;
  umkSaved: boolean;
}
export interface AcceptedWorkspaceMembership {
  workspaceId: string;
  workspaceName: string;
  roleName: string | null;
}
type InvitationAcceptanceOutcome = {
  status: "success";
  membership: AcceptedWorkspaceMembership | null;
};

function findWorkspaceInvitationCreatedEvent(
  events: Record<string, unknown>[],
  invitationId: string,
): Record<string, unknown> {
  const event = events.find((envelope) => {
    const payload = envelope.payload as Record<string, unknown> | undefined;
    const body = payload?.body as Record<string, unknown> | undefined;
    return (
      payload?.event_type === "workspace_invitation_created" && body?.invitation_id === invitationId
    );
  });
  if (!event) throw new Error("invitation_created_event_missing");
  return event;
}

async function assertWorkspaceInvitationBootstrapMatchesCreatedEvent(params: {
  lookupToken: string;
  bootstrapSecret: string | null;
  bootstrapPackage: Record<string, unknown>;
  plaintext: WorkspaceInvitationBootstrapPlaintext;
  createdEvents: Record<string, unknown>[];
}): Promise<void> {
  const event = findWorkspaceInvitationCreatedEvent(
    params.createdEvents,
    params.plaintext.invitation_id,
  );
  const payload = event.payload as Record<string, unknown> | undefined;
  const body = payload?.body as Record<string, unknown> | undefined;
  const redeemAuthority = body?.redeem_authority as Record<string, unknown> | undefined;
  const aad = params.bootstrapPackage.aad as Record<string, unknown> | undefined;
  const delivery = invitationDeliveryBinding(params.bootstrapPackage);
  const expectedCapabilityContextHash = blake3Base64Url(
    canonicalizeStrictBytes({
      invited_email: params.plaintext.invited_email,
      invitation_id: params.plaintext.invitation_id,
      role_id: params.plaintext.role_id,
      workspace_id: params.plaintext.workspace_id,
    } as StrictJsonValue),
  );
  if (
    body?.workspace_id !== params.plaintext.workspace_id ||
    body.invitation_id !== params.plaintext.invitation_id ||
    body.role_id !== params.plaintext.role_id ||
    body.kek_version !== params.plaintext.kek_version ||
    (delivery.deliveryMode === "unknown_fragment" &&
      (!params.bootstrapSecret ||
        body.bootstrap_key_commitment !==
          (await invitationSecretCommitment(
            params.lookupToken,
            params.bootstrapSecret,
            "workspace",
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
    throw new Error("invitation_bootstrap_created_event_mismatch");
  }
}

function invitationDeliveryBinding(bootstrapPackage: Record<string, unknown>): {
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
    throw new Error("invitation_recipient_binding_invalid");
  }
  const records = recipientWrap.wraps as Record<string, unknown>[];
  if (records.length === 0) throw new Error("invitation_recipient_binding_invalid");
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
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function retryAsync<T>(fn: () => Promise<T>, retries: number, delayMs = 0): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (delayMs > 0 && attempt < retries - 1) await delay(delayMs);
    }
  }
  throw lastError;
}
async function persistKekCopies(
  acceptResult: Pick<InvitationAcceptResult, "workspace_id" | "kek_version">,
  auth: AuthState,
  device: DeviceState,
  saveState: KekSaveState,
): Promise<KekSaveState> {
  let { deviceSaved, umkSaved } = saveState;
  if (!deviceSaved) {
    try {
      await retryAsync(
        () => resolveActiveKek(acceptResult.workspace_id, { auth, device }),
        MEMBER_ENVELOPE_MAX_RETRIES,
        MEMBER_ENVELOPE_RETRY_DELAY_MS,
      );
      deviceSaved = true;
    } catch {
      // Fall back to the identity-bound member envelope path below.
    }
  }
  if (!deviceSaved) {
    try {
      await retryAsync(
        () =>
          recoverWorkspaceInvitationMemberEnvelope(acceptResult.workspace_id, auth, {
            deviceId: device.deviceId,
          }),
        MEMBER_ENVELOPE_MAX_RETRIES,
        MEMBER_ENVELOPE_RETRY_DELAY_MS,
      );
      deviceSaved = true;
    } catch {
      // Retries exhausted for device envelope.
    }
  }
  umkSaved = deviceSaved;
  return { deviceSaved, umkSaved };
}

async function installInvitationBootstrapBeforeAccept(
  token: string,
  expectedRecipient: { userId: string; deviceId: string },
): Promise<{
  workspaceId: string;
  invitationId: string;
  keyVersion: number;
  workspaceKeyDirectoryCheckpoint: KeyDirectoryEnvelope;
  workspaceKeyDirectoryCheckpointAncestry: KeyDirectoryEnvelope[];
  workspaceKeyDirectoryEventAncestry: KeyDirectoryEnvelope[];
  plaintext: WorkspaceInvitationBootstrapPlaintext;
}> {
  const lookupToken = invitationLookupToken(token);
  const bootstrapSecret = invitationBootstrapSecret(token);
  const lookup = (await workspacesApi.lookupInvitation(lookupToken)) as InvitationLookupResult;
  if (lookup.kind !== "workspace" || !lookup.encrypted_bootstrap_package) {
    throw new Error("This invitation does not contain workspace key material.");
  }
  if (
    typeof lookup.invitation_id !== "string" ||
    typeof lookup.kek_version !== "number" ||
    !lookup.workspace_key_directory_checkpoint
  ) {
    throw new Error("This invitation is missing workspace trust state.");
  }
  const workspaceKeyDirectoryCheckpoint = assertKeyDirectoryEnvelope(
    lookup.workspace_key_directory_checkpoint,
    "invitation_workspace_key_directory_checkpoint_invalid",
  );
  const workspaceKeyDirectoryCheckpointAncestry =
    lookup.workspace_key_directory_checkpoint_ancestry.map((entry) =>
      assertKeyDirectoryEnvelope(entry, "invitation_workspace_checkpoint_ancestry_invalid"),
    );
  const workspaceKeyDirectoryEventAncestry = lookup.workspace_key_directory_event_ancestry.map(
    (entry) => assertKeyDirectoryEnvelope(entry, "invitation_workspace_event_ancestry_invalid"),
  );

  const worker = getCryptoWorker();
  const delivery = invitationDeliveryBinding(lookup.encrypted_bootstrap_package);
  if (delivery.deliveryMode === "unknown_fragment" && !bootstrapSecret) {
    throw new Error("This invitation link is missing encryption key material.");
  }
  if (
    delivery.deliveryMode === "known_recipient" &&
    (delivery.recipientUserId !== expectedRecipient.userId ||
      !delivery.recipientDeviceIds.includes(expectedRecipient.deviceId))
  ) {
    throw new Error("This invitation belongs to another account or device.");
  }
  const plaintext = assertWorkspaceInvitationBootstrapPlaintext(
    await worker.unwrapKekFromInvitationBootstrap({
      bootstrap: lookup.encrypted_bootstrap_package,
      ...(bootstrapSecret ? { bootstrapSecret } : {}),
    }),
  );

  const workspaceId = plaintext.workspace_id;
  const keyVersion = plaintext.kek_version;
  if (
    plaintext.invitation_id !== lookup.invitation_id ||
    keyVersion !== lookup.kek_version ||
    lookup.encrypted_bootstrap_package.workspace_id !== workspaceId ||
    lookup.encrypted_bootstrap_package.key_version !== keyVersion
  ) {
    throw new Error("Invitation key material is malformed.");
  }
  await assertWorkspaceInvitationBootstrapMatchesCreatedEvent({
    lookupToken,
    bootstrapSecret,
    bootstrapPackage: lookup.encrypted_bootstrap_package,
    plaintext,
    createdEvents: workspaceKeyDirectoryEventAncestry,
  });
  await pinWorkspaceCheckpointFromBootstrap({
    workspaceId,
    checkpointEnvelope: plaintext.workspace_key_directory_checkpoint,
    workspaceKeyDirectoryEventAncestry,
    workspacePinBootstrapHash: plaintext.workspace_pin_bootstrap_hash,
    workspacePinBootstrap: plaintext.workspace_pin_bootstrap,
  });

  await putOfflineKek({
    workspaceId,
    keyVersion,
    cachedAt: Date.now(),
  });

  return {
    workspaceId,
    invitationId: lookup.invitation_id,
    keyVersion,
    workspaceKeyDirectoryCheckpoint,
    workspaceKeyDirectoryCheckpointAncestry,
    workspaceKeyDirectoryEventAncestry,
    plaintext,
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

export async function acceptInvitationWithKekPersistence({
  token,
  auth,
  device,
}: {
  token: string;
  auth: AuthState;
  device: DeviceState;
}): Promise<InvitationAcceptanceOutcome> {
  const initialLookup = (await workspacesApi.lookupInvitation(
    invitationLookupToken(token),
  )) as InvitationLookupResult;
  if (initialLookup.kind === "workspace" && initialLookup.delivery_mode === "known_recipient") {
    return acceptKnownRecipientInvitation({ token, auth, device, lookup: initialLookup });
  }

  const maxAcceptAttempts = 2;
  let savedWorkspaceId: string | null = null;
  let membership: AcceptedWorkspaceMembership | null = null;
  let lastAcceptResult: Pick<InvitationAcceptResult, "workspace_id" | "kek_version"> | null = null;
  let saveState: KekSaveState = { deviceSaved: false, umkSaved: false };
  const bootstrap = await installInvitationBootstrapBeforeAccept(token, {
    userId: auth.user.id,
    deviceId: device.deviceId,
  });
  const publicKeys = await getCryptoWorker().getPublicKeys();
  if (
    !publicKeys.identityHybridEncryptionPublicKeyMaterial ||
    !publicKeys.deviceHybridSigningPublicKeyMaterial ||
    !publicKeys.deviceHybridEncryptionPublicKeyMaterial ||
    !publicKeys.deviceEncryptionKeyId
  ) {
    throw new Error("Device encryption keys are not available.");
  }
  const baseWorkspaceCheckpoint = await ensureWorkspaceCheckpointPinned({
    workspaceId: bootstrap.workspaceId,
    checkpointEnvelope: bootstrap.workspaceKeyDirectoryCheckpoint,
    checkpointAncestry: bootstrap.workspaceKeyDirectoryCheckpointAncestry,
    eventAncestry: bootstrap.workspaceKeyDirectoryEventAncestry,
  });
  const operationCheckpoint = operationCheckpointFromEnvelope(baseWorkspaceCheckpoint);
  let memberEnvelopeWrap = await getCryptoWorker().createSignedPqKekWrap({
    purpose: "workspace_member_kek_wrap",
    workspaceId: bootstrap.workspaceId,
    keyVersion: bootstrap.keyVersion,
    recipientPublicKeyMaterial: publicKeys.identityHybridEncryptionPublicKeyMaterial,
    senderUserId: auth.user.id,
    senderDeviceId: device.deviceId,
    resource: {
      workspace_id: bootstrap.workspaceId,
      target_user_id: auth.user.id,
      kek_version: bootstrap.keyVersion,
    },
    eventScope: {
      scope_kind: "workspace",
      scope_id: bootstrap.workspaceId,
    },
    operationCheckpoint,
  });
  const memberEnvelope = {
    target_user_id: auth.user.id,
    sender_device_id: device.deviceId,
    key_version: bootstrap.keyVersion,
    ...memberEnvelopeWrap,
  } as Record<string, unknown>;
  const keyDirectoryAppend = await buildWorkspaceInvitationRedeemedKeyDirectoryAppend({
    workspaceId: bootstrap.workspaceId,
    checkpointEnvelope: baseWorkspaceCheckpoint,
    invitationId: bootstrap.invitationId,
    redeemAuthoritySigningKeyId: bootstrap.plaintext.redeem_authority_signing_key_id,
    memberEnvelopeWrap,
    redeemedUserId: auth.user.id,
    redeemedDeviceId: device.deviceId,
    redeemedIdentityHybridEncryptionPublicKeyMaterial:
      publicKeys.identityHybridEncryptionPublicKeyMaterial,
    redeemedDeviceHybridSigningPublicKeyMaterial: publicKeys.deviceHybridSigningPublicKeyMaterial,
    redeemedDeviceHybridEncryptionPublicKeyMaterial:
      publicKeys.deviceHybridEncryptionPublicKeyMaterial,
    redeemedEncryptionKeyId: publicKeys.deviceEncryptionKeyId,
    memberEnvelopeKeyVersion: bootstrap.keyVersion,
    memberEnvelopeHash: memberEnvelopeWrap.event.wrap_event_body_hash,
  });
  memberEnvelopeWrap = await getCryptoWorker().finalizeSignedPqWrapOperationCheckpoint({
    record: memberEnvelopeWrap,
    operationCheckpoint: operationCheckpointFromEnvelope(keyDirectoryAppend.checkpoint),
  });
  const finalizedMemberEnvelope = {
    ...memberEnvelope,
    ...memberEnvelopeWrap,
  } as Record<string, unknown>;
  saveState = { deviceSaved: true, umkSaved: true };
  for (let attempt = 0; attempt < maxAcceptAttempts; attempt++) {
    let acceptResult: InvitationAcceptResult;
    try {
      const rawAcceptResult = await workspacesApi.acceptInvitation(invitationLookupToken(token), {
        member_envelope: finalizedMemberEnvelope as AcceptInvitationMemberEnvelope,
        workspace_key_directory_events: keyDirectoryAppend.events,
        workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
      });
      acceptResult = {
        ...rawAcceptResult,
        workspace_key_directory_checkpoint:
          rawAcceptResult.workspace_key_directory_checkpoint === undefined ||
          rawAcceptResult.workspace_key_directory_checkpoint === null
            ? rawAcceptResult.workspace_key_directory_checkpoint
            : assertKeyDirectoryEnvelope(
                rawAcceptResult.workspace_key_directory_checkpoint,
                "accepted_workspace_key_directory_checkpoint_invalid",
              ),
      };
    } catch (error) {
      if (
        error instanceof ApiError &&
        error.status === 410 &&
        error.body.error === "invitation_kek_outdated"
      ) {
        const bodyWorkspaceId =
          typeof error.body.workspace_id === "string" ? error.body.workspace_id : null;
        const recoveryWorkspaceId = savedWorkspaceId || bodyWorkspaceId;
        if (recoveryWorkspaceId) {
          try {
            await recoverWorkspaceInvitationMemberEnvelope(recoveryWorkspaceId, auth, {
              deviceId: device.deviceId,
            });
            return { status: "success", membership };
          } catch {
            // Member envelope not available yet.
          }
        }
        throw new Error(
          "This invitation uses an outdated encryption key. Please request a new invitation from the workspace administrator.",
        );
      }
      if (
        error instanceof ApiError &&
        error.status === 409 &&
        error.body.error === "kek_rotation_in_progress"
      ) {
        throw new Error(
          "A key rotation is currently in progress for this workspace. Please try again after the rotation is complete.",
        );
      }
      throw error;
    }
    if (
      acceptResult.workspace_id !== bootstrap.workspaceId ||
      acceptResult.kek_version !== bootstrap.keyVersion
    ) {
      throw new Error("Invitation key material does not match the accepted workspace.");
    }
    if (!acceptResult.workspace_key_directory_checkpoint) {
      throw new Error("Invitation acceptance is missing workspace trust state.");
    }
    if (
      hashKeyDirectoryCheckpointEnvelope(acceptResult.workspace_key_directory_checkpoint) !==
      hashKeyDirectoryCheckpointEnvelope(keyDirectoryAppend.checkpoint)
    ) {
      throw new Error("Invitation acceptance trust state does not match the submitted append.");
    }
    await advanceWorkspacePinWithAcceptedAppend({
      workspaceId: acceptResult.workspace_id,
      baseCheckpointEnvelope: baseWorkspaceCheckpoint,
      acceptedCheckpointEnvelope: keyDirectoryAppend.checkpoint,
      acceptedEventEnvelopes: keyDirectoryAppend.events,
      authorityEventAncestry: bootstrap.workspaceKeyDirectoryEventAncestry,
    });
    if (acceptResult.encrypted_bootstrap_package) {
      try {
        const publicKeys = await getCryptoWorker().getPublicKeys();
        if (publicKeys.deviceHybridEncryptionPublicKeyMaterial) {
          await persistWorkspaceKekForDevice({
            workspaceId: acceptResult.workspace_id,
            userId: auth.user.id,
            senderDeviceId: device.deviceId,
            targetDeviceId: device.deviceId,
            targetDeviceHybridEncryptionPublicKeyMaterial:
              publicKeys.deviceHybridEncryptionPublicKeyMaterial,
            keyVersion: acceptResult.kek_version,
            ignoreConflict: true,
          });
        }
      } catch {
        // The fragment bootstrap has already installed the KEK for this accept flow.
        // Server-side durable self-wrap may be retried by normal workspace bootstrap.
      }
    }
    savedWorkspaceId = acceptResult.workspace_id;
    membership ??= {
      workspaceId: acceptResult.workspace_id,
      workspaceName: acceptResult.workspace_name,
      roleName: acceptResult.role_name ?? null,
    };
    lastAcceptResult = acceptResult;
    saveState = await persistKekCopies(acceptResult, auth, device, saveState);
    if (saveState.deviceSaved && saveState.umkSaved) {
      return { status: "success", membership };
    }
    if (saveState.deviceSaved || saveState.umkSaved) {
      break;
    }
  }
  if (lastAcceptResult && !(saveState.deviceSaved && saveState.umkSaved)) {
    saveState = await persistKekCopies(lastAcceptResult, auth, device, saveState);
    if (saveState.deviceSaved && saveState.umkSaved) {
      return { status: "success", membership };
    }
  }
  throw new Error("Failed to complete invitation key setup. Please try again.");
}

async function acceptKnownRecipientInvitation(params: {
  token: string;
  auth: AuthState;
  device: DeviceState;
  lookup: InvitationLookupResult;
}): Promise<InvitationAcceptanceOutcome> {
  const { token, auth, device, lookup } = params;
  if (
    !lookup.invitation_id ||
    !lookup.workspace_key_directory_checkpoint ||
    lookup.recipient_user_id !== auth.user.id ||
    !lookup.recipient_device_ids.includes(device.deviceId)
  ) {
    throw new Error("This invitation belongs to another account or device.");
  }
  const attempt = await getApprovedWorkspaceDeliveryAttempt({
    token,
    lookup: lookup as components["schemas"]["InvitationLookupResponse"],
    auth,
    device,
  });
  const baseCheckpoint = assertKeyDirectoryEnvelope(
    lookup.workspace_key_directory_checkpoint,
    "invitation_workspace_key_directory_checkpoint_invalid",
  );
  const authorityEventAncestry = lookup.workspace_key_directory_event_ancestry.map((entry) =>
    assertKeyDirectoryEnvelope(entry, "invitation_workspace_event_ancestry_invalid"),
  );
  const artifacts = assertKnownWorkspaceDeliveryArtifacts(attempt);
  await verifyKnownWorkspaceAuthorization({
    attempt,
    artifacts,
    baseCheckpoint,
    authorityEventAncestry,
  });

  const acceptedCheckpoint = assertKeyDirectoryEnvelope(
    artifacts.workspace_key_directory_checkpoint,
    "accepted_workspace_key_directory_checkpoint_invalid",
  );
  const acceptedEvents = artifacts.workspace_key_directory_events.map((entry) =>
    assertKeyDirectoryEnvelope(entry, "accepted_workspace_key_directory_event_invalid"),
  );
  const recipientDeliveryAdmissionProof = {
    attempt,
    authorization: artifacts.authorization,
    freshnessProof: artifacts.redeem_freshness_proof,
    baseCheckpoint,
    currentCheckpoint: acceptedCheckpoint,
    authorityEventAncestry,
    acceptedEventAncestry: acceptedEvents,
  };
  assertRecipientDeliveryAdmissionBindings(recipientDeliveryAdmissionProof);

  const accepted = await workspacesApi.consumeWorkspaceInvitationDeliveryAttempt(
    attempt.redeem_attempt_id,
    { token: invitationLookupToken(token) },
  );
  if (
    !accepted.recipient_delivery_artifacts ||
    hash(accepted.recipient_delivery_artifacts) !== hash(artifacts)
  ) {
    throw new Error("Invitation key delivery response is malformed.");
  }
  await advanceWorkspacePinWithAcceptedAppend({
    workspaceId: accepted.workspace_id,
    baseCheckpointEnvelope: baseCheckpoint,
    acceptedCheckpointEnvelope: acceptedCheckpoint,
    acceptedEventEnvelopes: acceptedEvents,
    authorityEventAncestry,
  });

  const verifiedAdmission = await verifyRecipientDeliveryAdmission(recipientDeliveryAdmissionProof);

  const authorization = artifacts.authorization;
  const deliveryWrap = artifacts.delivery_wrap as unknown as SignedPqWrapRecord;
  const resource = deliveryWrap.resource as Record<string, unknown>;
  if (
    deliveryWrap.purpose !== "workspace_invitation_kek_wrap" ||
    resource.workspace_id !== accepted.workspace_id ||
    resource.invitation_id !== attempt.context_id ||
    resource.redeemed_user_id !== auth.user.id ||
    resource.redeemed_device_id !== device.deviceId ||
    resource.recipient_encryption_key_id !== attempt.target_encryption_key_id ||
    resource.kek_version !== accepted.kek_version
  ) {
    throw new Error("Invitation key delivery wrap is malformed.");
  }
  const operationProof = recipientDeliveryOperationProof(verifiedAdmission, {
    ...deliveryWrap,
    workspace_key_directory_checkpoint: acceptedCheckpoint,
    workspace_key_directory_checkpoint_ancestry: [baseCheckpoint],
    workspace_key_directory_event_ancestry: acceptedEvents,
  });
  await verifyWorkspaceSignedPqWrapOperation(accepted.workspace_id, operationProof);
  await getCryptoWorker().openRecipientBoundInvitationDeviceKekWrap({
    operationProof,
    recipientDeliveryAdmissionProof,
    senderSigningPublicKeyMaterial: authorization.hybrid_signing_public_key_material as never,
  });
  await getCryptoWorker().storeKekForOffline({
    workspaceId: accepted.workspace_id,
    keyVersion: accepted.kek_version,
  });
  await putOfflineKek({
    workspaceId: accepted.workspace_id,
    keyVersion: accepted.kek_version,
    cachedAt: Date.now(),
  });
  consumeLocalDeliveryAttempt(token);

  try {
    const publicKeys = await getCryptoWorker().getPublicKeys();
    if (publicKeys.deviceHybridEncryptionPublicKeyMaterial) {
      await persistWorkspaceKekForDevice({
        workspaceId: accepted.workspace_id,
        userId: auth.user.id,
        senderDeviceId: device.deviceId,
        targetDeviceId: device.deviceId,
        targetDeviceHybridEncryptionPublicKeyMaterial:
          publicKeys.deviceHybridEncryptionPublicKeyMaterial,
        keyVersion: accepted.kek_version,
        ignoreConflict: true,
      });
    }
  } catch {
    // The member envelope remains the durable recovery path for this accepted invitation.
  }

  return {
    status: "success",
    membership: {
      workspaceId: accepted.workspace_id,
      workspaceName: accepted.workspace_name,
      roleName: accepted.role_name ?? null,
    },
  };
}

interface KnownWorkspaceDeliveryArtifacts {
  authorization: Record<string, unknown>;
  redeem_freshness_proof: Record<string, unknown>;
  workspace_pin_bootstrap: Record<string, unknown>;
  delivery_wrap: Record<string, unknown>;
  member_envelope: Record<string, unknown>;
  workspace_key_directory_events: Record<string, unknown>[];
  workspace_key_directory_checkpoint: Record<string, unknown>;
}

function assertKnownWorkspaceDeliveryArtifacts(
  attempt: DeliveryAttempt,
): KnownWorkspaceDeliveryArtifacts {
  const value = attempt.approved_artifacts as Record<string, unknown>;
  const required = [
    "authorization",
    "delivery_wrap",
    "member_envelope",
    "redeem_freshness_proof",
    "workspace_key_directory_checkpoint",
    "workspace_key_directory_events",
    "workspace_pin_bootstrap",
  ];
  if (
    !value ||
    Object.keys(value).sort().join("\u0000") !== required.sort().join("\u0000") ||
    !Array.isArray(value.workspace_key_directory_events)
  ) {
    throw new Error("Invitation key delivery artifacts are malformed.");
  }
  for (const key of required.filter((entry) => entry !== "workspace_key_directory_events")) {
    const candidate = value[key];
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
      throw new Error("Invitation key delivery artifacts are malformed.");
    }
  }
  return value as unknown as KnownWorkspaceDeliveryArtifacts;
}

async function verifyKnownWorkspaceAuthorization(params: {
  attempt: DeliveryAttempt;
  artifacts: KnownWorkspaceDeliveryArtifacts;
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
    payload.version !== 1 ||
    payload.redeem_attempt_id !== attempt.redeem_attempt_id ||
    payload.context_kind !== attempt.context_kind ||
    payload.context_id !== attempt.context_id ||
    payload.resource_hash !== attempt.resource_hash ||
    payload.recipient_redeem_nonce !== attempt.recipient_redeem_nonce ||
    payload.recipient_nonce_state_hash !== attempt.recipient_nonce_state_hash ||
    payload.live_redeem_challenge_hash !== attempt.live_redeem_challenge_hash ||
    payload.redeem_freshness_proof_hash !== hash(freshness) ||
    payload.current_checkpoint_sequence !== checkpointPayload.sequence ||
    payload.current_checkpoint_hash !== hashKeyDirectoryCheckpointEnvelope(baseCheckpoint) ||
    payload.current_event_head_sequence !== coveredHead.head_sequence ||
    payload.current_event_head_hash !== coveredHead.head_hash
  ) {
    throw new Error("Invitation key delivery authorization is malformed.");
  }
  const signerPublic = authorization.hybrid_signing_public_key_material as never;
  const signingKeyId = stringField(authorization.signing_key_id);
  const ownerId = stringField((signerPublic as Record<string, unknown>).owner_id);
  const freshnessDevice = freshness.authoritative_device as Record<string, unknown>;
  const expectedTranscript = buildRecipientBoundAuthorizationTranscript({
    ownerId,
    actorUserId: stringField(freshnessDevice.user_id),
    actorDeviceId: stringField(freshnessDevice.device_id),
    signingKeyId,
    authorizationPayload: payload,
  });
  if (
    hash(expectedTranscript) !== hash(authorization.transcript) ||
    !verifyRecipientBoundAuthorizationSignature({
      transcript: expectedTranscript,
      signature: authorization.signature as never,
      publicKeyMaterial: signerPublic,
    })
  ) {
    throw new Error("Invitation key delivery authorization signature is invalid.");
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

function hash(value: unknown): string {
  return blake3Base64Url(canonicalizeStrictBytes(value as StrictJsonValue));
}
