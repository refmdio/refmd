import { ApiError, encryptionApi, workspacesApi } from "@/shared/api";
import type { components } from "@/shared/api/schema";
import type { AuthState, DeviceState } from "@/entities/session";
import {
  installWorkspaceOperationCheckpointPin,
  resolveActiveKek,
} from "@/shared/lib/crypto/kek-resolver";
import { buildWorkspaceInvitationRedeemedKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/invitation-events";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  rememberVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { persistWorkspaceKekForDevice } from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { type SignedPqWrapRecord } from "@/shared/lib/crypto/signed-pq-wrap";
import { putOfflineKek } from "@/shared/lib/offline/storage/store";
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
}
interface InvitationLookupResult {
  kind: "workspace" | "guest";
  invitation_id?: string;
  kek_version?: number;
  encrypted_bootstrap_package?: Record<string, unknown> | null;
  workspace_key_directory_checkpoint?: KeyDirectoryEnvelope | null;
  workspace_key_directory_checkpoint_ancestry?: KeyDirectoryEnvelope[];
  workspace_key_directory_event_ancestry?: KeyDirectoryEnvelope[];
}
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
  bootstrapSecret: string;
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
    body.bootstrap_key_commitment !==
      (await invitationSecretCommitment(params.lookupToken, params.bootstrapSecret, "workspace")) ||
    body.bootstrap_package_hash !==
      blake3Base64Url(canonicalizeStrictBytes(params.bootstrapPackage as StrictJsonValue)) ||
    body.bootstrap_suite_id !== "refmd-v2-invitation-bootstrap-xchacha20poly1305" ||
    body.capability_context_hash !== expectedCapabilityContextHash ||
    redeemAuthority?.signing_key_id !== params.plaintext.redeem_authority_signing_key_id
  ) {
    throw new Error("invitation_bootstrap_created_event_mismatch");
  }
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
async function recoverFromMemberEnvelope(
  workspaceId: string,
  auth: AuthState,
  device: Pick<DeviceState, "deviceId" | "deviceEcdhPublic">,
): Promise<void> {
  const envelope = await encryptionApi.getMemberEnvelopeWithRrp(workspaceId);
  if (!envelope) throw new Error("member_envelope_missing");
  const worker = getCryptoWorker();
  const expectedOperationCheckpoint = await installWorkspaceOperationCheckpointPin(
    workspaceId,
    envelope as unknown as Record<string, unknown>,
  );
  await worker.openSignedPqMemberKekWrap({
    record: envelope as unknown as SignedPqWrapRecord,
    senderSigningPublicKeyMaterial:
      envelope.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    expectedOperationCheckpoint,
  });
  const publicKeys = await worker.getPublicKeys();
  if (!publicKeys.deviceHybridEncryptionPublicKeyMaterial) {
    throw new Error("Device hybrid encryption key material is not available.");
  }
  await persistWorkspaceKekForDevice({
    workspaceId,
    userId: auth.user.id,
    senderDeviceId: device.deviceId,
    targetDeviceId: device.deviceId,
    targetDeviceHybridEncryptionPublicKeyMaterial:
      publicKeys.deviceHybridEncryptionPublicKeyMaterial,
    keyVersion: envelope.key_version,
    ignoreConflict: true,
  });
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
          recoverFromMemberEnvelope(acceptResult.workspace_id, auth, {
            deviceId: device.deviceId,
            deviceEcdhPublic: device.deviceEcdhPublic,
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

async function installInvitationBootstrapBeforeAccept(token: string): Promise<{
  workspaceId: string;
  invitationId: string;
  keyVersion: number;
  bootstrapSecret: string;
  workspaceKeyDirectoryCheckpoint: KeyDirectoryEnvelope;
  workspaceKeyDirectoryCheckpointAncestry: KeyDirectoryEnvelope[];
  workspaceKeyDirectoryEventAncestry: KeyDirectoryEnvelope[];
  plaintext: WorkspaceInvitationBootstrapPlaintext;
}> {
  const lookupToken = invitationLookupToken(token);
  const bootstrapSecret = invitationBootstrapSecret(token);
  if (!bootstrapSecret) {
    throw new Error("This invitation link is missing encryption key material.");
  }

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
  const workspaceKeyDirectoryCheckpointAncestry = (
    lookup.workspace_key_directory_checkpoint_ancestry ?? []
  ).map((entry) =>
    assertKeyDirectoryEnvelope(entry, "invitation_workspace_checkpoint_ancestry_invalid"),
  );
  const workspaceKeyDirectoryEventAncestry = (
    lookup.workspace_key_directory_event_ancestry ?? []
  ).map((entry) =>
    assertKeyDirectoryEnvelope(entry, "invitation_workspace_event_ancestry_invalid"),
  );

  const worker = getCryptoWorker();
  const plaintext = assertWorkspaceInvitationBootstrapPlaintext(
    await worker.unwrapKekFromInvitationBootstrap({
      bootstrap: lookup.encrypted_bootstrap_package,
      bootstrapSecret,
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
    bootstrapSecret,
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
    rememberVerifiedKeyDirectoryLineage({
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
  const maxAcceptAttempts = 2;
  let savedWorkspaceId: string | null = null;
  let membership: AcceptedWorkspaceMembership | null = null;
  let lastAcceptResult: Pick<InvitationAcceptResult, "workspace_id" | "kek_version"> | null = null;
  let saveState: KekSaveState = { deviceSaved: false, umkSaved: false };
  const bootstrap = await installInvitationBootstrapBeforeAccept(token);
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
            await recoverFromMemberEnvelope(recoveryWorkspaceId, auth, {
              deviceId: device.deviceId,
              deviceEcdhPublic: device.deviceEcdhPublic,
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
