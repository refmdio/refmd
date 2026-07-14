import { blake3Base64Url } from "../hash";
import { computeHybridEncryptionKeyId } from "../hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import { computeSigningKeyId } from "../signature";

import {
  activeDeviceSigningKeyId,
  actorWithCheckpointAuthority,
  appendKeyEntryIfMissing,
  checkpointShareParticipantKeys,
  deviceActor,
  eventHash,
  eventHead,
  eventRef,
  invitationRedeemActor,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  keyEntry,
  nextWorkspaceSequence,
  numberField,
  signCheckpoint,
  signEvent,
  signInvitationRedeemCheckpoint,
  signInvitationRedeemEvent,
  stringField,
} from "./primitives";
import { wrapIssuedKeyDirectoryEventFromRecord } from "./wrap-events";
import type {
  GuestInvitationCreatedKeyDirectoryAppendInput,
  GuestInvitationRedeemedKeyDirectoryAppendInput,
  GuestInvitationRevokedKeyDirectoryAppendInput,
  KeyDirectoryAppendArtifacts,
  WorkspaceInvitationCreatedKeyDirectoryAppendInput,
  WorkspaceInvitationRedeemedKeyDirectoryAppendInput,
  WorkspaceInvitationRevokedKeyDirectoryAppendInput,
} from "./types";

export async function buildWorkspaceInvitationCreatedKeyDirectoryAppend(
  input: WorkspaceInvitationCreatedKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  return buildWorkspaceNoopKeyDirectoryAppend(input, "workspace_invitation_created", {
    workspace_id: input.workspaceId,
    invitation_id: input.invitationId,
    invitee_binding: {
      kind: "email",
      email_hash: blake3Base64Url(
        canonicalizeStrictBytes({ email: input.invitedEmail.trim().toLowerCase() }),
      ),
    },
    role_id: input.roleId ?? "",
    base_role: input.baseRole,
    delivery_mode: input.deliveryMode,
    recipient_user_id: input.recipientUserId ?? "NOT_APPLICABLE",
    recipient_device_ids: [...input.recipientDeviceIds].sort(),
    kek_version: input.kekVersion,
    expires_event_sequence: input.expiresEventSequence,
    redeem_authority: {
      signer_kind: "invitation_redeem_authority",
      signing_key_id: input.redeemAuthority.signingKeyId,
      hybrid_signing_public_key_material: input.redeemAuthority.hybridSigningPublicKeyMaterial,
    },
    bootstrap_key_commitment: input.bootstrapKeyCommitment,
    bootstrap_package_hash: input.bootstrapPackageHash,
    bootstrap_suite_id: input.bootstrapSuiteId,
    capability_context_hash: input.capabilityContextHash,
  });
}

export async function buildWorkspaceInvitationRevokedKeyDirectoryAppend(
  input: WorkspaceInvitationRevokedKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  return buildWorkspaceNoopKeyDirectoryAppend(input, "workspace_invitation_revoked", {
    workspace_id: input.workspaceId,
    invitation_id: input.invitationId,
    revoked_at_event_sequence: nextWorkspaceSequence(input.checkpointEnvelope),
    reason: input.reason ?? "revoked",
  });
}

export async function buildGuestInvitationCreatedKeyDirectoryAppend(
  input: GuestInvitationCreatedKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  return buildWorkspaceNoopKeyDirectoryAppend(input, "guest_invitation_created", {
    workspace_id: input.workspaceId,
    guest_invitation_id: input.invitationId,
    guest_grant_template_hash: blake3Base64Url(
      canonicalizeStrictBytes({
        guest_invitation_id: input.invitationId,
        permission: input.permission,
        scope_id: input.scopeId,
        scope_kind: input.scopeKind,
        workspace_id: input.workspaceId,
      }),
    ),
    scope_kind: input.scopeKind,
    scope_id: input.scopeId,
    permission: input.permission,
    delivery_mode: input.deliveryMode,
    recipient_user_id: input.recipientUserId ?? "NOT_APPLICABLE",
    recipient_device_ids: [...input.recipientDeviceIds].sort(),
    key_version_context: {
      workspace_kek_version: input.keyVersionContext.workspaceKekVersion,
      share_key_version: input.keyVersionContext.shareKeyVersion,
      dek_version: input.keyVersionContext.dekVersion,
    },
    allowed_share_ids_hash: blake3Base64Url(
      canonicalizeStrictBytes({
        allowed_share_ids: [...input.allowedShareIds].sort((a, b) => a.localeCompare(b)),
      }),
    ),
    expires_event_sequence: input.expiresEventSequence,
    redeem_authority: {
      signer_kind: "invitation_redeem_authority",
      signing_key_id: input.redeemAuthority.signingKeyId,
      hybrid_signing_public_key_material: input.redeemAuthority.hybridSigningPublicKeyMaterial,
    },
    bootstrap_key_commitment: input.bootstrapKeyCommitment,
    bootstrap_package_hash: input.bootstrapPackageHash,
    bootstrap_suite_id: input.bootstrapSuiteId,
    capability_context_hash: input.capabilityContextHash,
  });
}

export async function buildGuestInvitationRevokedKeyDirectoryAppend(
  input: GuestInvitationRevokedKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  return buildWorkspaceNoopKeyDirectoryAppend(input, "guest_invitation_revoked", {
    workspace_id: input.workspaceId,
    guest_invitation_id: input.invitationId,
    revoked_at_event_sequence: nextWorkspaceSequence(input.checkpointEnvelope),
    reason: input.reason ?? "revoked",
  });
}

export async function buildWorkspaceInvitationRedeemedKeyDirectoryAppend(
  input: WorkspaceInvitationRedeemedKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  const redeemedIdentityEncryptionKeyId = computeHybridEncryptionKeyId(
    input.redeemedIdentityHybridEncryptionPublicKeyMaterial,
  );
  const redeemedDeviceSigningKeyId = computeSigningKeyId(
    input.redeemedDeviceHybridSigningPublicKeyMaterial,
  );
  const redeemedDeviceEncryptionKeyId = computeHybridEncryptionKeyId(
    input.redeemedDeviceHybridEncryptionPublicKeyMaterial,
  );
  if (redeemedDeviceEncryptionKeyId !== input.redeemedEncryptionKeyId) {
    throw new Error("workspace_invitation_redeemed_device_encryption_key_mismatch");
  }

  const wrapIssuedEvent = wrapIssuedKeyDirectoryEventFromRecord({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    coveredHead,
    wrapRecord: input.memberEnvelopeWrap,
  });
  const redeemedEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(coveredHead.head_sequence) + 2,
    eventType: "workspace_invitation_redeemed",
    actor: invitationRedeemActor({
      invitationId: input.invitationId,
      signingKeyId: input.redeemAuthoritySigningKeyId,
    }),
    previousEventHash: eventHash(wrapIssuedEvent),
    body: {
      workspace_id: input.workspaceId,
      invitation_id: input.invitationId,
      redeemed_user_id: input.redeemedUserId,
      redeemed_device_id: input.redeemedDeviceId,
      redeemed_encryption_key_id: input.redeemedEncryptionKeyId,
      member_envelope_key_version: input.memberEnvelopeKeyVersion,
      member_envelope_hash: input.memberEnvelopeHash,
      redeemed_at_event_sequence: numberField(coveredHead.head_sequence) + 2,
    },
  });

  const signedEvents = [
    await signEvent("device", wrapIssuedEvent),
    await signInvitationRedeemEvent(input.invitationId, redeemedEvent),
  ];
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(redeemedEvent),
    identityKeys: [
      ...((checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? []),
      keyEntry(
        redeemedIdentityEncryptionKeyId,
        input.redeemedIdentityHybridEncryptionPublicKeyMaterial,
        eventRef("workspace", input.workspaceId, redeemedEvent),
      ),
    ],
    deviceKeys: [
      ...((checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? []),
      keyEntry(
        redeemedDeviceSigningKeyId,
        input.redeemedDeviceHybridSigningPublicKeyMaterial,
        eventRef("workspace", input.workspaceId, redeemedEvent),
      ),
      keyEntry(
        input.redeemedEncryptionKeyId,
        input.redeemedDeviceHybridEncryptionPublicKeyMaterial,
        eventRef("workspace", input.workspaceId, redeemedEvent),
      ),
    ],
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signInvitationRedeemCheckpoint(input.invitationId, checkpoint);
  return { events: signedEvents, checkpoint: signedCheckpoint };
}

export async function buildGuestInvitationRedeemedKeyDirectoryAppend(
  input: GuestInvitationRedeemedKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  const guestIdentityEncryptionKeyId = computeHybridEncryptionKeyId(
    input.guestIdentityHybridEncryptionPublicKeyMaterial,
  );
  const guestDeviceSigningKeyId = computeSigningKeyId(
    input.guestDeviceHybridSigningPublicKeyMaterial,
  );
  const guestDeviceEncryptionKeyId = computeHybridEncryptionKeyId(
    input.guestDeviceHybridEncryptionPublicKeyMaterial,
  );
  if (guestDeviceSigningKeyId !== input.guestSigningKeyId) {
    throw new Error("guest_invitation_redeemed_device_signing_key_mismatch");
  }
  if (guestDeviceEncryptionKeyId !== input.guestEncryptionKeyId) {
    throw new Error("guest_invitation_redeemed_device_encryption_key_mismatch");
  }

  const redeemedEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "guest_invitation_redeemed",
    actor: invitationRedeemActor({
      invitationId: input.invitationId,
      signingKeyId: input.redeemAuthoritySigningKeyId,
    }),
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      workspace_id: input.workspaceId,
      guest_invitation_id: input.invitationId,
      guest_grant_id: input.guestGrantId,
      guest_user_id: input.guestUserId,
      guest_device_id: input.guestDeviceId,
      guest_encryption_key_id: input.guestEncryptionKeyId,
      guest_signing_key_id: input.guestSigningKeyId,
      scope_kind: input.scopeKind,
      scope_id: input.scopeId,
      permission: input.permission,
      recipient_account_user_id: input.recipientAccountUserId ?? "NOT_APPLICABLE",
      recipient_account_device_id: input.recipientAccountDeviceId ?? "NOT_APPLICABLE",
      redeemed_at_event_sequence: numberField(coveredHead.head_sequence) + 1,
    },
  });

  const signedEvents = [await signInvitationRedeemEvent(input.invitationId, redeemedEvent)];
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(redeemedEvent),
    identityKeys: appendKeyEntryIfMissing(
      (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
      keyEntry(
        guestIdentityEncryptionKeyId,
        input.guestIdentityHybridEncryptionPublicKeyMaterial,
        eventRef("workspace", input.workspaceId, redeemedEvent),
      ),
    ),
    deviceKeys: appendKeyEntryIfMissing(
      appendKeyEntryIfMissing(
        (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
        keyEntry(
          input.guestSigningKeyId,
          input.guestDeviceHybridSigningPublicKeyMaterial,
          eventRef("workspace", input.workspaceId, redeemedEvent),
        ),
      ),
      keyEntry(
        input.guestEncryptionKeyId,
        input.guestDeviceHybridEncryptionPublicKeyMaterial,
        eventRef("workspace", input.workspaceId, redeemedEvent),
      ),
    ),
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signInvitationRedeemCheckpoint(input.invitationId, checkpoint);
  return { events: signedEvents, checkpoint: signedCheckpoint };
}

async function buildWorkspaceNoopKeyDirectoryAppend(
  input: {
    workspaceId: string;
    actorUserId: string;
    actorDeviceId: string;
    checkpointEnvelope: Record<string, unknown>;
  },
  eventType: string,
  body: Record<string, unknown>,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");

  const actor = actorWithCheckpointAuthority(
    deviceActor(
      input.actorUserId,
      input.actorDeviceId,
      activeDeviceSigningKeyId(checkpointPayload, input.actorDeviceId),
    ),
    "workspace",
    input.workspaceId,
    checkpointPayload,
  );
  const event = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType,
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body,
  });

  const signedEvent = await signEvent("device", event);
  const shareParticipantKeys = checkpointShareParticipantKeys(checkpointPayload);
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(event),
    identityKeys: (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
    deviceKeys: (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys,
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint("device", "workspace_authorized", checkpoint);
  return { events: [signedEvent], checkpoint: signedCheckpoint };
}
