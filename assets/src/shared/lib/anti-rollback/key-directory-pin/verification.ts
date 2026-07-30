import type { KeyDirectoryPin, SignedKeyDirectoryEnvelope } from "./types";
import { pinFromCheckpoint } from "./core";
import {
  applyEventToCheckpointPayload,
  assertAndApplyRotationReplayState,
  applyAuthoritySeedEventsToCheckpointPayload,
  eventSignatureAuthorityPayload,
  rotationReplayStateFromAuthorityEvents,
  verifyEventSemantics,
  type RotationReplayState,
} from "./replay";
import {
  checkpointSignatureAuthorityPayload,
  isInvitationAdmissionWrapEvent,
  isRecipientBoundDeliveryWrapEvent,
  isRecipientBoundGuestRedeemEvent,
  isRecipientBoundWorkspaceRedeemEvent,
  verifyCheckpointSignatures,
  verifyEventSignatures,
  assertShareParticipantCheckpointAdvance,
} from "./signatures";
import {
  assertCheckpointStateMatchesReplay,
  checkpointHash,
  eventHash,
  genesisCandidateSigningKeyId,
  isGenesisCandidateEvent,
  numberField,
} from "./primitives";

export { assertShareParticipantCheckpointAdvance, pinFromCheckpoint, verifyCheckpointSignatures };

export async function verifyCheckpointAncestry(
  scopeKind: "user" | "workspace",
  scopeId: string,
  current: KeyDirectoryPin,
  ancestry: SignedKeyDirectoryEnvelope[],
  candidate: SignedKeyDirectoryEnvelope,
  events: SignedKeyDirectoryEnvelope[] = [],
  authoritySeedEvents: SignedKeyDirectoryEnvelope[] = [],
): Promise<void> {
  if (ancestry.length < 1) throw new Error("key_directory_checkpoint_ancestry_required");
  const anchor = ancestry[0]!;
  const anchorPin = pinFromCheckpoint(scopeKind, scopeId, anchor);
  if (
    anchorPin.checkpointSequence !== current.checkpointSequence ||
    anchorPin.checkpointHash !== current.checkpointHash
  ) {
    throw new Error("key_directory_checkpoint_anchor_mismatch");
  }

  const chain = [...ancestry, candidate];
  for (let i = 1; i < chain.length; i += 1) {
    const previous = chain[i - 1]!;
    const next = chain[i]!;
    const previousHash = checkpointHash(previous);
    const nextPayload = next.payload;

    if (nextPayload.scope_kind !== scopeKind || nextPayload.scope_id !== scopeId) {
      throw new Error("key_directory_checkpoint_scope_mismatch");
    }
    if (
      numberField(nextPayload.sequence, "checkpoint_sequence_invalid") !==
      i + current.checkpointSequence
    ) {
      throw new Error("key_directory_checkpoint_sequence_gap");
    }
    if (nextPayload.previous_checkpoint_hash !== previousHash) {
      throw new Error("key_directory_checkpoint_previous_hash_mismatch");
    }

    await verifyCheckpointSignatures(
      next,
      checkpointSignatureAuthorityPayload(next, previous.payload, events, authoritySeedEvents),
      previous.payload,
    );
  }
}

export async function verifyInitialReplay(
  scopeKind: "user" | "workspace",
  scopeId: string,
  events: SignedKeyDirectoryEnvelope[],
  checkpoint: SignedKeyDirectoryEnvelope,
): Promise<void> {
  if (events.length < 1) throw new Error("key_directory_initial_events_required");
  let previousHash: string | null = null;
  let expectedSequence = 1;
  let rotationState: RotationReplayState = {};
  let replayPayload: Record<string, unknown> = {
    ...checkpoint.payload,
    identity_keys: [],
    device_keys: [],
    share_participant_keys: [],
    revoked_key_ids: [],
  };
  const genesisSigningKeyId = genesisCandidateSigningKeyId(
    scopeKind,
    scopeId,
    events,
    checkpoint.payload,
  );

  for (const event of events) {
    if (event.payload.scope_kind !== scopeKind || event.payload.scope_id !== scopeId) {
      throw new Error("key_directory_event_scope_mismatch");
    }
    if (numberField(event.payload.sequence, "event_sequence_invalid") !== expectedSequence) {
      throw new Error("key_directory_event_sequence_gap");
    }
    if (expectedSequence === 1) {
      if ("previous_event_hash" in event.payload) {
        throw new Error("key_directory_event_previous_hash_mismatch");
      }
    } else if (event.payload.previous_event_hash !== previousHash) {
      throw new Error("key_directory_event_previous_hash_mismatch");
    }
    verifyEventSemantics(event, checkpoint.payload);
    rotationState = assertAndApplyRotationReplayState(rotationState, event);
    await verifyEventSignatures(event, checkpoint.payload, {
      allowInactiveSigner: isGenesisCandidateEvent(event.payload, genesisSigningKeyId),
    });
    replayPayload = applyEventToCheckpointPayload(replayPayload, event, checkpoint.payload);
    previousHash = eventHash(event);
    expectedSequence += 1;
  }

  const coveredHead = checkpoint.payload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  if (
    coveredHead.head_sequence !== expectedSequence - 1 ||
    coveredHead.head_hash !== previousHash
  ) {
    throw new Error("key_directory_checkpoint_event_head_mismatch");
  }
  assertCheckpointStateMatchesReplay(checkpoint.payload, replayPayload);
  await verifyCheckpointSignatures(checkpoint, checkpoint.payload);
}

export async function verifyEventAncestry(
  scopeKind: "user" | "workspace",
  scopeId: string,
  current: KeyDirectoryPin,
  events: SignedKeyDirectoryEnvelope[],
  candidate: SignedKeyDirectoryEnvelope,
  authorityPayload: Record<string, unknown>,
  authoritySeedEvents: SignedKeyDirectoryEnvelope[] = [],
): Promise<void> {
  if (events.length < 1) throw new Error("key_directory_event_ancestry_required");

  let previousHash = current.eventHeadHash;
  let expectedSequence = current.eventHeadSequence + 1;
  let rotationState = rotationReplayStateFromAuthorityEvents(authoritySeedEvents, events);
  let replayPayload = applyAuthoritySeedEventsToCheckpointPayload(
    authorityPayload,
    authoritySeedEvents,
  );
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (!event) throw new Error("key_directory_event_invalid");
    const nextEvent = events[index + 1];
    const payload = event.payload;
    if (payload.scope_kind !== scopeKind || payload.scope_id !== scopeId) {
      throw new Error("key_directory_event_scope_mismatch");
    }
    if (numberField(payload.sequence, "event_sequence_invalid") !== expectedSequence) {
      throw new Error("key_directory_event_sequence_gap");
    }
    if (payload.previous_event_hash !== previousHash) {
      throw new Error("key_directory_event_previous_hash_mismatch");
    }
    const admissionWrap = isInvitationAdmissionWrapEvent(event, nextEvent);
    const deliveryWrap = isRecipientBoundDeliveryWrapEvent(event, events);
    const recipientBoundWorkspaceRedeem = isRecipientBoundWorkspaceRedeemEvent(event, events);
    const recipientBoundGuestRedeem = isRecipientBoundGuestRedeemEvent(event, events);
    const recipientBoundRedeem = recipientBoundWorkspaceRedeem || recipientBoundGuestRedeem;
    const userScopedWrap = admissionWrap || deliveryWrap;
    verifyEventSemantics(event, candidate.payload, {
      allowInactiveWrapPrincipal: admissionWrap,
      allowUserScopedWrapRecipient: userScopedWrap,
    });
    rotationState = assertAndApplyRotationReplayState(rotationState, event);
    await verifyEventSignatures(
      event,
      admissionWrap
        ? candidate.payload
        : recipientBoundRedeem
          ? replayPayload
          : eventSignatureAuthorityPayload(event, replayPayload, candidate.payload),
      { allowInactiveSigner: admissionWrap },
    );
    previousHash = eventHash(event);
    expectedSequence += 1;
    replayPayload = applyEventToCheckpointPayload(replayPayload, event, candidate.payload, {
      allowInactiveWrapPrincipal: admissionWrap,
      allowUserScopedWrapRecipient: userScopedWrap,
      recipientBoundWorkspaceRedeem,
      recipientBoundGuestRedeem,
    });
  }

  const coveredHead = candidate.payload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  if (
    coveredHead.head_sequence !== expectedSequence - 1 ||
    coveredHead.head_hash !== previousHash
  ) {
    throw new Error("key_directory_checkpoint_event_head_mismatch");
  }
  assertCheckpointStateMatchesReplay(candidate.payload, replayPayload);
}
