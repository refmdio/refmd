import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import type { SignedKeyDirectoryEnvelope } from "./types";
import {
  arrayField,
  assertKeyEntryValidFromEvent,
  assertOwner,
  eventRefFor,
  findKeyEntryById,
  isRecord,
  keyEntryById,
  numberField,
  stringField,
  updateKeyEntries,
  updateKeyEntriesIfMissing,
} from "./primitives";

export function applyInvitationCreatedEventToCheckpointPayload(
  replayPayload: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
): Record<string, unknown> {
  const body = event.payload.body as Record<string, unknown>;
  const redeemAuthority = body.redeem_authority as Record<string, unknown> | undefined;
  if (!redeemAuthority) throw new Error("invitation_redeem_authority_missing");
  const signingKeyId = stringField(redeemAuthority.signing_key_id, "signing_key_id_invalid");
  const keyMaterial = redeemAuthority.hybrid_signing_public_key_material;
  if (
    !isRecord(keyMaterial) ||
    computeSigningKeyId(keyMaterial as unknown as HybridSigningPublicKeyMaterial) !== signingKeyId
  ) {
    throw new Error("invitation_redeem_authority_key_mismatch");
  }
  if (keyMaterial.owner_kind !== "invitation_redeem_authority") {
    throw new Error("invitation_redeem_authority_owner_kind_invalid");
  }
  const expectedInvitationId =
    event.payload.event_type === "workspace_invitation_created"
      ? stringField(body.invitation_id, "invitation_id_invalid")
      : stringField(body.guest_invitation_id, "guest_invitation_id_invalid");
  if (keyMaterial.owner_id !== expectedInvitationId) {
    throw new Error("invitation_redeem_authority_owner_id_mismatch");
  }
  const authorityEntry = {
    key_id: signingKeyId,
    key_material: keyMaterial,
    valid_from: eventRefFor(event),
    expires_event_sequence: numberField(
      body.expires_event_sequence,
      "expires_event_sequence_invalid",
    ),
    invitation_id: expectedInvitationId,
  };

  return {
    ...replayPayload,
    temporary_authority_keys: [
      ...arrayField(replayPayload.temporary_authority_keys),
      authorityEntry,
    ],
  };
}

export function invitationRedeemAuthorityPayloadForEvent(
  checkpointPayload: Record<string, unknown>,
  redeemEvent: SignedKeyDirectoryEnvelope,
  events: SignedKeyDirectoryEnvelope[],
): Record<string, unknown> {
  const body = redeemEvent.payload.body as Record<string, unknown>;
  const eventType = redeemEvent.payload.event_type;
  const invitationId =
    eventType === "workspace_invitation_redeemed"
      ? stringField(body.invitation_id, "invitation_id_invalid")
      : stringField(body.guest_invitation_id, "guest_invitation_id_invalid");
  const createdEventType =
    eventType === "workspace_invitation_redeemed"
      ? "workspace_invitation_created"
      : "guest_invitation_created";
  const invitationIdField =
    eventType === "workspace_invitation_redeemed" ? "invitation_id" : "guest_invitation_id";
  const revokedEventType =
    eventType === "workspace_invitation_redeemed"
      ? "workspace_invitation_revoked"
      : "guest_invitation_revoked";
  const redeemSequence = numberField(redeemEvent.payload.sequence, "event_sequence_invalid");
  const createdEvent = events
    .filter((event) => event.payload.event_type === createdEventType)
    .find((event) => {
      const createdBody = event.payload.body as Record<string, unknown>;
      return createdBody[invitationIdField] === invitationId;
    });
  if (!createdEvent) throw new Error("invitation_redeem_authority_created_event_missing");

  const createdBody = createdEvent.payload.body as Record<string, unknown>;
  const expires = numberField(createdBody.expires_event_sequence, "expires_event_sequence_invalid");
  if (redeemSequence >= expires) throw new Error("invitation_redeem_authority_expired");

  const inactive = events.some((event) => {
    const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
    if (
      sequence <= numberField(createdEvent.payload.sequence, "event_sequence_invalid") ||
      sequence >= redeemSequence ||
      (event.payload.event_type !== revokedEventType && event.payload.event_type !== eventType)
    ) {
      return false;
    }
    const eventBody = event.payload.body as Record<string, unknown>;
    return eventBody[invitationIdField] === invitationId;
  });
  if (inactive) throw new Error("invitation_redeem_authority_inactive");

  return applyInvitationCreatedEventToCheckpointPayload(checkpointPayload, createdEvent);
}

export function assertTemporaryInvitationAuthorityActive(
  replayPayload: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
): void {
  const signer = event.signatures.find(
    (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "invitation_redeem_authority",
  )?.signer;
  if (!signer) throw new Error("invitation_redeem_authority_signer_missing");
  const signingKeyId = stringField(signer.signing_key_id, "signing_key_id_invalid");
  const entry = findKeyEntryById(replayPayload, signingKeyId);
  if (!entry) throw new Error("invitation_redeem_authority_inactive");
  const expires = numberField(entry.expires_event_sequence, "expires_event_sequence_invalid");
  if (numberField(event.payload.sequence, "event_sequence_invalid") >= expires) {
    throw new Error("invitation_redeem_authority_expired");
  }
}

export function removeTemporaryInvitationAuthority(
  replayPayload: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
): Record<string, unknown> {
  const body = event.payload.body as Record<string, unknown>;
  const invitationId =
    event.payload.event_type === "workspace_invitation_revoked" ||
    event.payload.event_type === "workspace_invitation_redeemed"
      ? stringField(body.invitation_id, "invitation_id_invalid")
      : stringField(body.guest_invitation_id, "guest_invitation_id_invalid");

  return {
    ...replayPayload,
    temporary_authority_keys: arrayField(replayPayload.temporary_authority_keys).filter(
      (entry) => !isRecord(entry) || entry.invitation_id !== invitationId,
    ),
  };
}

export function assertInvitationRedeemAuthoritySigner(
  event: SignedKeyDirectoryEnvelope,
  invitationId: string,
): void {
  const signer = event.signatures.find(
    (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "invitation_redeem_authority",
  )?.signer;
  if (!signer) throw new Error("invitation_redeem_authority_signer_missing");
  if (signer.invitation_id !== invitationId) {
    throw new Error("invitation_redeem_authority_invitation_id_mismatch");
  }
}

export function applyWorkspaceInvitationRedeemedEventToCheckpointPayload(
  replayPayload: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
  candidatePayload: Record<string, unknown>,
  recipientBound = false,
): Record<string, unknown> {
  const body = event.payload.body as Record<string, unknown>;
  if (recipientBound) {
    const actor = event.payload.actor as Record<string, unknown>;
    const signer = event.signatures.find(
      (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "device",
    )?.signer;
    if (
      !signer ||
      signer.user_id !== actor.user_id ||
      signer.device_id !== actor.device_id ||
      signer.signing_key_id !== actor.signing_key_id
    ) {
      throw new Error("device_signer_actor_mismatch");
    }
  } else {
    assertInvitationRedeemAuthoritySigner(
      event,
      stringField(body.invitation_id, "invitation_id_invalid"),
    );
  }
  const identityEntry = keyEntryByOwnerProtocol(
    candidatePayload,
    "identity",
    stringField(body.redeemed_user_id, "redeemed_user_id_invalid"),
    "refmd.hybrid-encryption-key-material",
  );
  const signingEntry = keyEntryByOwnerProtocol(
    candidatePayload,
    "device",
    stringField(body.redeemed_device_id, "redeemed_device_id_invalid"),
    "refmd.hybrid-signing-key-material",
  );
  const encryptionEntry = keyEntryById(
    candidatePayload,
    stringField(body.redeemed_encryption_key_id, "redeemed_encryption_key_id_invalid"),
  );
  const deviceId = stringField(body.redeemed_device_id, "redeemed_device_id_invalid");

  assertOwner(
    identityEntry.key_material,
    "identity",
    stringField(body.redeemed_user_id, "redeemed_user_id_invalid"),
  );
  assertOwner(signingEntry.key_material, "device", deviceId);
  assertOwner(encryptionEntry.key_material, "device", deviceId);
  assertKeyEntryValidFromEvent(identityEntry, event);
  assertKeyEntryValidFromEvent(signingEntry, event);
  assertKeyEntryValidFromEvent(encryptionEntry, event);

  return updateKeyEntries(
    updateKeyEntries(
      updateKeyEntries(replayPayload, "identity_keys", identityEntry),
      "device_keys",
      signingEntry,
    ),
    "device_keys",
    encryptionEntry,
  );
}

export function applyGuestInvitationRedeemedEventToCheckpointPayload(
  replayPayload: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
  candidatePayload: Record<string, unknown>,
  recipientBound = false,
): Record<string, unknown> {
  const body = event.payload.body as Record<string, unknown>;
  if (recipientBound) {
    const actor = event.payload.actor as Record<string, unknown>;
    const signer = event.signatures.find(
      (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "device",
    )?.signer;
    if (
      !signer ||
      signer.user_id !== actor.user_id ||
      signer.device_id !== actor.device_id ||
      signer.signing_key_id !== actor.signing_key_id
    ) {
      throw new Error("device_signer_actor_mismatch");
    }
  } else {
    assertInvitationRedeemAuthoritySigner(
      event,
      stringField(body.guest_invitation_id, "guest_invitation_id_invalid"),
    );
  }
  const signingKeyId = stringField(body.guest_signing_key_id, "guest_signing_key_id_invalid");
  const encryptionKeyId = stringField(
    body.guest_encryption_key_id,
    "guest_encryption_key_id_invalid",
  );
  const userId = stringField(body.guest_user_id, "guest_user_id_invalid");
  const existingIdentityEntry = findKeyEntryByOwnerProtocol(
    replayPayload,
    "identity",
    userId,
    "refmd.hybrid-encryption-key-material",
  );
  const existingSigningEntry = findKeyEntryById(replayPayload, signingKeyId);
  const existingEncryptionEntry = findKeyEntryById(replayPayload, encryptionKeyId);
  const identityEntry =
    existingIdentityEntry ??
    keyEntryByOwnerProtocol(
      candidatePayload,
      "identity",
      userId,
      "refmd.hybrid-encryption-key-material",
    );
  const signingEntry = existingSigningEntry ?? keyEntryById(candidatePayload, signingKeyId);
  const encryptionEntry =
    existingEncryptionEntry ?? keyEntryById(candidatePayload, encryptionKeyId);
  const deviceId = stringField(body.guest_device_id, "guest_device_id_invalid");

  assertOwner(identityEntry.key_material, "identity", userId);
  assertOwner(signingEntry.key_material, "device", deviceId);
  assertOwner(encryptionEntry.key_material, "device", deviceId);
  if (!existingIdentityEntry) assertKeyEntryValidFromEvent(identityEntry, event);
  if (!existingSigningEntry) assertKeyEntryValidFromEvent(signingEntry, event);
  if (!existingEncryptionEntry) assertKeyEntryValidFromEvent(encryptionEntry, event);

  return updateKeyEntriesIfMissing(
    updateKeyEntriesIfMissing(
      updateKeyEntriesIfMissing(replayPayload, "identity_keys", identityEntry),
      "device_keys",
      signingEntry,
    ),
    "device_keys",
    encryptionEntry,
  );
}

function keyEntryByOwnerProtocol(
  checkpointPayload: Record<string, unknown>,
  ownerKind: string,
  ownerId: string,
  protocol: string,
): Record<string, unknown> {
  const entry = findKeyEntryByOwnerProtocol(checkpointPayload, ownerKind, ownerId, protocol);
  if (entry) return entry;
  throw new Error("key_directory_owner_key_entry_missing");
}

function findKeyEntryByOwnerProtocol(
  checkpointPayload: Record<string, unknown>,
  ownerKind: string,
  ownerId: string,
  protocol: string,
): Record<string, unknown> | null {
  for (const entry of [
    ...arrayField(checkpointPayload.identity_keys),
    ...arrayField(checkpointPayload.device_keys),
    ...arrayField(checkpointPayload.share_participant_keys),
    ...arrayField(checkpointPayload.temporary_authority_keys),
  ]) {
    if (!isRecord(entry) || !isRecord(entry.key_material)) continue;
    if (
      entry.key_material.owner_kind === ownerKind &&
      entry.key_material.owner_id === ownerId &&
      entry.key_material.protocol === protocol
    ) {
      return entry;
    }
  }
  return null;
}
