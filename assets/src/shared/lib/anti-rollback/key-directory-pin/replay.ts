import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { currentSuitePolicy } from "@/shared/lib/crypto/suite";
import type { SignedKeyDirectoryEnvelope } from "./types";
import {
  applyGuestInvitationRedeemedEventToCheckpointPayload,
  applyInvitationCreatedEventToCheckpointPayload,
  applyWorkspaceInvitationRedeemedEventToCheckpointPayload,
  assertTemporaryInvitationAuthorityActive,
  removeTemporaryInvitationAuthority,
} from "./invitation-replay";
import {
  arrayField,
  assertKeyEntryActiveAtSequence,
  assertKeyEntryValidFromEvent,
  assertOwner,
  eventHash,
  isRecord,
  keyEntryById,
  keyEntryValidFromEvent,
  numberField,
  revokeKeyEntry,
  shareParticipantKeyEntryById,
  shareParticipantSignerDeviceId,
  shareParticipantSignerKeyId,
  stringField,
  updateKeyEntries,
} from "./primitives";

export type RotationReplayState = Record<
  string,
  {
    status: "started" | "completed" | "deleted";
    newKeyVersion?: number;
    startedEventHash?: string;
    completedEventHash?: string;
  }
>;

export function eventSignatureAuthorityPayload(
  event: SignedKeyDirectoryEnvelope,
  replayPayload: Record<string, unknown>,
  candidatePayload: Record<string, unknown>,
): Record<string, unknown> {
  if (
    event.payload.event_type === "workspace_invitation_redeemed" ||
    event.payload.event_type === "guest_invitation_redeemed"
  ) {
    assertTemporaryInvitationAuthorityActive(replayPayload, event);
  }

  return event.payload.event_type === "document_update_accepted" ||
    event.payload.event_type === "document_snapshot_accepted"
    ? candidatePayload
    : replayPayload;
}

export function applyAuthoritySeedEventsToCheckpointPayload(
  checkpointPayload: Record<string, unknown>,
  events: SignedKeyDirectoryEnvelope[],
): Record<string, unknown> {
  return events.reduce((payload, event) => {
    switch (event.payload.event_type) {
      case "workspace_invitation_created":
      case "guest_invitation_created":
        return applyInvitationCreatedEventToCheckpointPayload(payload, event);
      case "workspace_invitation_revoked":
      case "workspace_invitation_redeemed":
      case "guest_invitation_revoked":
      case "guest_invitation_redeemed":
        return removeTemporaryInvitationAuthority(payload, event);
      default:
        return payload;
    }
  }, checkpointPayload);
}

export function verifyEventSemantics(
  event: SignedKeyDirectoryEnvelope,
  checkpointPayload: Record<string, unknown>,
  options: { allowInactiveWrapPrincipal?: boolean } = {},
): void {
  const body = event.payload.body as Record<string, unknown> | undefined;
  if (!body) throw new Error("key_directory_event_body_invalid");
  switch (event.payload.event_type) {
    case "identity_key_added": {
      const entry = keyEntryById(checkpointPayload, stringField(body.key_id, "key_id_invalid"));
      assertKeyMaterialHash(entry, body.key_material_hash, "identity_key_material_hash_mismatch");
      break;
    }
    case "device_key_added": {
      const signingEntry = keyEntryById(
        checkpointPayload,
        stringField(body.signing_key_id, "signing_key_id_invalid"),
      );
      const encryptionEntry = keyEntryById(
        checkpointPayload,
        stringField(body.encryption_key_id, "encryption_key_id_invalid"),
      );
      assertOwner(
        signingEntry.key_material,
        "device",
        stringField(body.device_id, "device_id_invalid"),
      );
      assertOwner(
        encryptionEntry.key_material,
        "device",
        stringField(body.device_id, "device_id_invalid"),
      );
      break;
    }
    case "member_added":
      if (body.workspace_id !== event.payload.scope_id) {
        throw new Error("member_added_scope_mismatch");
      }
      break;
    case "member_removed":
      if (body.removed_at_event_sequence !== event.payload.sequence) {
        throw new Error("member_removed_sequence_mismatch");
      }
      break;
    case "suite_policy_changed": {
      const policy = currentSuitePolicy();
      if (
        body.suite_policy_version !== policy.suite_policy_version ||
        body.min_suite_rank !== policy.min_suite_rank ||
        JSON.stringify(body.allowed_suite_ids) !== JSON.stringify(policy.allowed_suite_ids)
      ) {
        throw new Error("suite_policy_mismatch");
      }
      break;
    }
    case "rotation_started":
    case "rotation_completed":
    case "old_key_deleted":
      if (
        body.event_type !== event.payload.event_type ||
        body.scope_kind !== event.payload.scope_kind ||
        body.scope_id !== event.payload.scope_id
      ) {
        throw new Error("rotation_event_scope_mismatch");
      }
      assertRotationSequence(event.payload.event_type, body, event.payload.sequence);
      break;
    case "document_snapshot_accepted":
    case "document_update_accepted":
      assertDocumentAdmissionSemantics(event, checkpointPayload, body);
      break;
    case "signing_key_revoked":
    case "encryption_key_revoked":
      if (body.revoked_at_event_sequence !== event.payload.sequence) {
        throw new Error("key_revoked_sequence_mismatch");
      }
      break;
    case "wrap_issued": {
      const resourceHash = blake3Base64Url(
        canonicalizeStrictBytes(body.resource as StrictJsonValue),
      );
      if (body.resource_hash !== resourceHash) throw new Error("wrap_resource_hash_mismatch");
      const actor = event.payload.actor as Record<string, unknown> | undefined;
      const sender = body.sender as Record<string, unknown> | undefined;
      const recipient = body.recipient as Record<string, unknown> | undefined;
      if (!actor || !sender || !recipient) throw new Error("wrap_principal_invalid");
      if (
        actor.user_id !== sender.user_id ||
        actor.device_id !== sender.device_id ||
        actor.signing_key_id !== sender.signing_key_id ||
        sender.key_scope_kind !== event.payload.scope_kind ||
        sender.key_scope_id !== event.payload.scope_id ||
        recipient.key_scope_kind !== event.payload.scope_kind ||
        recipient.key_scope_id !== event.payload.scope_id
      ) {
        throw new Error("wrap_principal_mismatch");
      }
      const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
      if (!options.allowInactiveWrapPrincipal) {
        assertKeyEntryActiveAtSequence(
          checkpointPayload,
          stringField(sender.signing_key_id, "signing_key_id_invalid"),
          sequence,
        );
        assertKeyEntryActiveAtSequence(
          checkpointPayload,
          stringField(recipient.encryption_key_id, "encryption_key_id_invalid"),
          sequence,
        );
      }
      break;
    }
    case "share_created":
    case "share_revoked":
    case "share_metadata_updated":
    case "share_key_scope_added":
    case "share_key_scope_removed":
    case "share_key_scope_replaced":
    case "share_exclusion_changed":
    case "recipient_bound_delivery_admitted": {
      assertWorkspaceScopedEvent(event, body, "share_event_workspace_mismatch");
      const actor = event.payload.actor as Record<string, unknown> | undefined;
      if (!actor || actor.signer_kind !== "device") throw new Error("share_event_actor_invalid");
      const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
      assertKeyEntryActiveAtSequence(
        checkpointPayload,
        stringField(actor.signing_key_id, "signing_key_id_invalid"),
        sequence,
      );
      assertShareEventSequence(event, body);
      break;
    }
    case "workspace_invitation_created":
    case "workspace_invitation_revoked":
    case "workspace_invitation_bootstrap_updated":
    case "workspace_invitation_redeemed":
    case "guest_invitation_created":
    case "guest_invitation_revoked":
    case "guest_invitation_bootstrap_updated":
    case "guest_invitation_redeemed":
    case "guest_grant_revoked":
    case "guest_device_revoked":
      assertWorkspaceScopedEvent(event, body, "invitation_workspace_mismatch");
      assertInvitationEventSequence(event, body);
      break;
    default:
      throw new Error(
        `key_directory_event_semantic_validator_missing:${String(event.payload.event_type)}`,
      );
  }
}

function assertDocumentAdmissionSemantics(
  event: SignedKeyDirectoryEnvelope,
  checkpointPayload: Record<string, unknown>,
  body: Record<string, unknown>,
): void {
  if (
    body.event_type !== event.payload.event_type ||
    body.workspace_id !== event.payload.scope_id
  ) {
    throw new Error("document_admission_scope_mismatch");
  }

  const actor = event.payload.actor as Record<string, unknown> | undefined;
  if (!actor) throw new Error("document_admission_actor_invalid");

  const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
  if (actor.signer_kind === "share_participant_device") {
    if (
      body.share_authority_kind !== "share_participant_device" ||
      body.share_permission !== "edit" ||
      typeof body.share_id !== "string" ||
      typeof body.share_session_id !== "string"
    ) {
      throw new Error("document_admission_share_participant_scope_missing");
    }
    if (actor.share_id !== body.share_id) {
      throw new Error("document_admission_share_participant_share_mismatch");
    }

    const signingKeyId = shareParticipantSignerKeyId(event);
    const deviceId = shareParticipantSignerDeviceId(event);
    if (signingKeyId !== actor.signing_key_id || deviceId !== actor.share_participant_device_id) {
      throw new Error("document_admission_share_participant_signer_mismatch");
    }

    const entry = keyEntryById(
      checkpointPayload,
      stringField(actor.signing_key_id, "signing_key_id_invalid"),
    );
    assertKeyEntryActiveAtSequence(
      checkpointPayload,
      stringField(actor.signing_key_id, "signing_key_id_invalid"),
      sequence,
    );
    assertOwner(
      entry.key_material,
      "share_participant_device",
      stringField(actor.share_participant_device_id, "share_participant_device_id_invalid"),
    );
    return;
  }

  if (
    "share_id" in body ||
    "share_session_id" in body ||
    "share_permission" in body ||
    "share_authority_kind" in body
  ) {
    throw new Error("document_admission_share_scope_for_workspace_actor");
  }
}

export function applyEventToCheckpointPayload(
  replayPayload: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
  candidatePayload: Record<string, unknown>,
  options: { allowInactiveWrapPrincipal?: boolean } = {},
): Record<string, unknown> {
  verifyEventSemantics(event, candidatePayload, options);

  switch (event.payload.event_type) {
    case "identity_key_added": {
      const entries = arrayField(candidatePayload.identity_keys).filter(
        (entry) =>
          isRecord(entry) &&
          keyEntryValidFromEvent(entry, event) &&
          isRecord(entry.key_material) &&
          entry.key_material.owner_kind === "identity",
      );
      if (entries.length === 0) throw new Error("key_directory_key_entry_missing");
      return entries.reduce<Record<string, unknown>>(
        (payload, entry) => updateKeyEntries(payload, "identity_keys", entry),
        replayPayload,
      );
    }
    case "device_key_added": {
      const body = event.payload.body as Record<string, unknown>;
      const signingEntry = keyEntryById(
        candidatePayload,
        stringField(body.signing_key_id, "signing_key_id_invalid"),
      );
      const encryptionEntry = keyEntryById(
        candidatePayload,
        stringField(body.encryption_key_id, "encryption_key_id_invalid"),
      );
      assertKeyEntryValidFromEvent(signingEntry, event);
      assertKeyEntryValidFromEvent(encryptionEntry, event);
      return updateKeyEntries(
        updateKeyEntries(replayPayload, "device_keys", signingEntry),
        "device_keys",
        encryptionEntry,
      );
    }
    case "signing_key_revoked":
    case "encryption_key_revoked":
      return revokeKeyEntry(
        replayPayload,
        stringField((event.payload.body as Record<string, unknown>).key_id, "key_id_invalid"),
        event,
      );
    case "document_snapshot_accepted":
    case "document_update_accepted":
      return applyDocumentAdmissionEventToCheckpointPayload(replayPayload, event, candidatePayload);
    case "suite_policy_changed":
      return applySuitePolicyChangedEventToCheckpointPayload(replayPayload, event);
    case "member_added":
    case "member_removed":
      return replayPayload;
    case "guest_invitation_created":
    case "workspace_invitation_created":
      return applyInvitationCreatedEventToCheckpointPayload(replayPayload, event);
    case "guest_invitation_revoked":
    case "workspace_invitation_revoked":
      return removeTemporaryInvitationAuthority(replayPayload, event);
    case "guest_invitation_bootstrap_updated":
    case "guest_grant_revoked":
    case "guest_device_revoked":
    case "old_key_deleted":
    case "rotation_completed":
    case "rotation_started":
    case "share_created":
    case "share_exclusion_changed":
    case "share_key_scope_added":
    case "share_key_scope_removed":
    case "share_key_scope_replaced":
    case "share_metadata_updated":
    case "recipient_bound_delivery_admitted":
    case "share_revoked":
    case "wrap_issued":
    case "workspace_invitation_bootstrap_updated":
      return replayPayload;
    case "workspace_invitation_redeemed":
      return removeTemporaryInvitationAuthority(
        applyWorkspaceInvitationRedeemedEventToCheckpointPayload(
          replayPayload,
          event,
          candidatePayload,
        ),
        event,
      );
    case "guest_invitation_redeemed":
      return removeTemporaryInvitationAuthority(
        applyGuestInvitationRedeemedEventToCheckpointPayload(
          replayPayload,
          event,
          candidatePayload,
        ),
        event,
      );
    default:
      throw new Error(
        `key_directory_event_semantic_validator_missing:${String(event.payload.event_type)}`,
      );
  }
}

function assertKeyMaterialHash(
  entry: Record<string, unknown>,
  expected: unknown,
  error: string,
): void {
  const actual = blake3Base64Url(canonicalizeStrictBytes(entry.key_material as StrictJsonValue));
  if (expected !== actual) throw new Error(error);
}

function assertWorkspaceScopedEvent(
  event: SignedKeyDirectoryEnvelope,
  body: Record<string, unknown>,
  error: string,
): void {
  if (event.payload.scope_kind !== "workspace" || body.workspace_id !== event.payload.scope_id) {
    throw new Error(error);
  }
}

function assertShareEventSequence(
  event: SignedKeyDirectoryEnvelope,
  body: Record<string, unknown>,
): void {
  const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
  switch (event.payload.event_type) {
    case "share_revoked":
      if (body.revoked_at_event_sequence !== sequence)
        throw new Error("share_revoked_sequence_mismatch");
      return;
    case "share_metadata_updated":
      if (body.updated_at_event_sequence !== sequence)
        throw new Error("share_metadata_updated_sequence_mismatch");
      return;
    case "share_key_scope_added":
      if (body.added_at_event_sequence !== sequence)
        throw new Error("share_key_scope_added_sequence_mismatch");
      return;
    case "share_key_scope_replaced":
      if (body.replaced_at_event_sequence !== sequence)
        throw new Error("share_key_scope_replaced_sequence_mismatch");
      return;
    case "share_key_scope_removed":
      if (body.removed_at_event_sequence !== sequence)
        throw new Error("share_key_scope_removed_sequence_mismatch");
      return;
    case "share_exclusion_changed":
      if (body.changed_at_event_sequence !== sequence)
        throw new Error("share_exclusion_changed_sequence_mismatch");
      return;
    case "recipient_bound_delivery_admitted":
      if (
        body.previous_workspace_event_sequence !== sequence - 1 ||
        body.previous_workspace_event_hash !== event.payload.previous_event_hash
      ) {
        throw new Error("recipient_delivery_previous_event_mismatch");
      }
      return;
  }
}

function assertInvitationEventSequence(
  event: SignedKeyDirectoryEnvelope,
  body: Record<string, unknown>,
): void {
  const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
  switch (event.payload.event_type) {
    case "workspace_invitation_revoked":
    case "guest_invitation_revoked":
    case "guest_grant_revoked":
    case "guest_device_revoked":
      if (body.revoked_at_event_sequence !== sequence) {
        throw new Error(`${String(event.payload.event_type)}_sequence_mismatch`);
      }
      return;
    case "workspace_invitation_bootstrap_updated":
    case "guest_invitation_bootstrap_updated":
      if (body.updated_at_event_sequence !== sequence) {
        throw new Error(`${String(event.payload.event_type)}_sequence_mismatch`);
      }
      return;
    case "workspace_invitation_redeemed":
    case "guest_invitation_redeemed":
      if (body.redeemed_at_event_sequence !== sequence) {
        throw new Error(`${String(event.payload.event_type)}_sequence_mismatch`);
      }
      return;
  }
}

function assertRotationSequence(
  eventType: unknown,
  body: Record<string, unknown>,
  sequenceValue: unknown,
): void {
  const sequence = numberField(sequenceValue, "event_sequence_invalid");
  if (eventType === "rotation_started") {
    if (body.not_before_event_sequence !== sequence) {
      throw new Error("rotation_started_sequence_mismatch");
    }
    assertRotationVersionProgression(body);
    return;
  }
  if (eventType === "rotation_completed") {
    if (body.completed_at_event_sequence !== sequence) {
      throw new Error("rotation_completed_sequence_mismatch");
    }
    assertRotationVersionProgression(body);
    return;
  }
  if (eventType === "old_key_deleted" && body.deleted_at_event_sequence !== sequence) {
    throw new Error("old_key_deleted_sequence_mismatch");
  }
}

export function assertAndApplyRotationReplayState(
  state: RotationReplayState,
  event: SignedKeyDirectoryEnvelope,
): RotationReplayState {
  const eventType = event.payload.event_type;
  if (
    eventType !== "rotation_started" &&
    eventType !== "rotation_completed" &&
    eventType !== "old_key_deleted"
  ) {
    return state;
  }

  const body = event.payload.body;
  if (!isRecord(body)) throw new Error("key_directory_event_body_invalid");
  const key = rotationReplayKey(body);
  const current = state[key];

  if (eventType === "rotation_started") {
    if (current) throw new Error("rotation_already_recorded");
    return {
      ...state,
      [key]: {
        status: "started",
        newKeyVersion: numberField(body.new_key_version, "new_key_version_invalid"),
        startedEventHash: eventHash(event),
      },
    };
  }

  if (eventType === "rotation_completed") {
    if (!current) throw new Error("rotation_started_event_missing");
    if (current.status !== "started") throw new Error("rotation_not_in_progress");
    const newKeyVersion = numberField(body.new_key_version, "new_key_version_invalid");
    if (current.newKeyVersion !== newKeyVersion) {
      throw new Error("rotation_key_version_mismatch");
    }
    return {
      ...state,
      [key]: {
        ...current,
        status: "completed",
        completedEventHash: eventHash(event),
      },
    };
  }

  if (!current || current.status !== "completed") {
    throw new Error("rotation_completed_event_missing");
  }
  return {
    ...state,
    [key]: {
      ...current,
      status: "deleted",
    },
  };
}

function rotationReplayKey(body: Record<string, unknown>): string {
  return [
    stringField(body.rotation_kind, "rotation_kind_invalid"),
    stringField(body.scope_kind, "scope_kind_invalid"),
    stringField(body.scope_id, "scope_id_invalid"),
    String(numberField(body.old_key_version, "old_key_version_invalid")),
  ].join(":");
}

function assertRotationVersionProgression(body: Record<string, unknown>): void {
  if (
    numberField(body.new_key_version, "new_key_version_invalid") <=
    numberField(body.old_key_version, "old_key_version_invalid")
  ) {
    throw new Error("rotation_key_version_not_increasing");
  }
}

function applySuitePolicyChangedEventToCheckpointPayload(
  replayPayload: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
): Record<string, unknown> {
  const body = event.payload.body as Record<string, unknown>;
  const allowedSuiteIds = arrayField(body.allowed_suite_ids).map((suiteId) =>
    stringField(suiteId, "suite_id_invalid"),
  );
  const allowedSuiteIdsHash = blake3Base64Url(
    canonicalizeStrictBytes({ allowed_suite_ids: allowedSuiteIds }),
  );
  return {
    ...replayPayload,
    suite_policy_version: body.suite_policy_version,
    min_suite_rank: body.min_suite_rank,
    allowed_suite_ids: allowedSuiteIds,
    allowed_suite_ids_hash: allowedSuiteIdsHash,
  };
}

function applyDocumentAdmissionEventToCheckpointPayload(
  replayPayload: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
  candidatePayload: Record<string, unknown>,
): Record<string, unknown> {
  const signerKeyId = shareParticipantSignerKeyId(event);
  if (!signerKeyId) return replayPayload;

  const entry = shareParticipantKeyEntryById(candidatePayload, signerKeyId);
  assertKeyEntryActiveAtSequence(
    candidatePayload,
    signerKeyId,
    numberField(event.payload.sequence, "event_sequence_invalid"),
  );
  assertOwner(
    entry.key_material,
    "share_participant_device",
    shareParticipantSignerDeviceId(event),
  );
  if (
    arrayField(replayPayload.share_participant_keys).some(
      (item) => isRecord(item) && item.key_id === signerKeyId,
    )
  ) {
    return replayPayload;
  }
  return updateKeyEntries(replayPayload, "share_participant_keys", entry);
}
