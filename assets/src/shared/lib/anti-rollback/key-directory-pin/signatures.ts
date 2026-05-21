import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type { HybridSignature } from "@/shared/lib/crypto/signature-types";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { SignedKeyDirectoryEnvelope } from "./types";
import {
  applyAuthoritySeedEventsToCheckpointPayload,
  applyEventToCheckpointPayload,
  eventSignatureAuthorityPayload,
} from "./replay";
import { invitationRedeemAuthorityPayloadForEvent } from "./invitation-replay";
import {
  arrayField,
  assertActorMatchesSigner,
  assertKeyEntryActiveAtSequence,
  assertSignerMatchesMaterial,
  checkpointSignatureVariant,
  eventHash,
  isRecord,
  isRequiredCheckpointSigner,
  numberField,
  sameCheckpointStateEntries,
  shareParticipantKeyEntryById,
  signingKeyMaterialById,
  stringField,
} from "./primitives";

export function isInvitationAdmissionWrapEvent(
  event: SignedKeyDirectoryEnvelope,
  nextEvent: SignedKeyDirectoryEnvelope | undefined,
): boolean {
  if (event.payload.event_type !== "wrap_issued" || !nextEvent) return false;
  const body = event.payload.body as Record<string, unknown> | undefined;
  const sender = body?.sender as Record<string, unknown> | undefined;
  const recipient = body?.recipient as Record<string, unknown> | undefined;
  const nextBody = nextEvent.payload.body as Record<string, unknown> | undefined;
  if (!body || !sender || !recipient || !nextBody) return false;
  if (body.purpose !== "workspace_member_kek_wrap") return false;
  if (nextEvent.payload.event_type !== "workspace_invitation_redeemed") return false;
  return (
    recipient.user_id === nextBody.redeemed_user_id &&
    sender.user_id === nextBody.redeemed_user_id &&
    sender.device_id === nextBody.redeemed_device_id
  );
}

export async function verifyCheckpointSignatures(
  checkpoint: SignedKeyDirectoryEnvelope,
  authorityPayload: Record<string, unknown>,
  previousPayload?: Record<string, unknown>,
): Promise<void> {
  const signingKeys = signingKeyMaterialById(authorityPayload);
  const checkpointSigningKeys = signingKeyMaterialById(checkpoint.payload);
  const coveredHead = checkpoint.payload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");

  const requiredSignatureKeyIds = new Set<string>();
  for (const signatureEnvelope of checkpoint.signatures) {
    const signer = signatureEnvelope.signer;
    const signingKeyId = stringField(signer.signing_key_id, "signing_key_id_invalid");
    const variant = checkpointSignatureVariant(checkpoint.payload, signer, previousPayload);
    const material =
      signingKeys.get(signingKeyId) ??
      (variant === "device_authorized" ? checkpointSigningKeys.get(signingKeyId) : undefined);
    if (!material) throw new Error("key_directory_checkpoint_signer_unknown");
    assertSignerMatchesMaterial(signer, material);
    const activePayload =
      signer.signer_kind === "invitation_redeem_authority" ? authorityPayload : checkpoint.payload;
    const activeHead = activePayload.covered_event_head as Record<string, unknown> | undefined;
    if (!activeHead) throw new Error("key_directory_checkpoint_head_invalid");
    assertKeyEntryActiveAtSequence(
      activePayload,
      signingKeyId,
      numberField(activeHead.head_sequence, "event_head_sequence_invalid"),
    );
    const valid = await getCryptoWorker().verifyKeyDirectoryCheckpointSignature({
      variant,
      checkpointPayload: checkpoint.payload as StrictJsonValue,
      signature: signatureEnvelope.signature as HybridSignature,
      publicKeyMaterial: material,
      signer: signer as StrictJsonValue,
    });
    if (!valid) throw new Error("key_directory_checkpoint_signature_invalid");
    if (isRequiredCheckpointSigner(checkpoint.payload, signer)) {
      requiredSignatureKeyIds.add(signingKeyId);
    }
  }

  if (requiredSignatureKeyIds.size < requiredCheckpointSignatureCount(checkpoint.payload)) {
    throw new Error("key_directory_checkpoint_required_signature_missing");
  }
}

function requiredCheckpointSignatureCount(payload: Record<string, unknown>): number {
  if (payload.scope_kind !== "user" || payload.sequence === 1) return 1;
  const entries = payload.identity_keys;
  if (!Array.isArray(entries)) return 1;
  const activeIdentityKeys = entries.filter(
    (entry) =>
      isRecord(entry) &&
      isRecord(entry.key_material) &&
      entry.key_material.owner_kind === "identity" &&
      entry.key_material.protocol === "refmd.hybrid-signing-key-material" &&
      !Object.prototype.hasOwnProperty.call(entry, "revoked_at"),
  );
  return activeIdentityKeys.length >= 2 ? 2 : 1;
}

export function checkpointSignatureAuthorityPayload(
  checkpoint: SignedKeyDirectoryEnvelope,
  previousPayload: Record<string, unknown>,
  events: SignedKeyDirectoryEnvelope[] = [],
  authoritySeedEvents: SignedKeyDirectoryEnvelope[] = [],
): Record<string, unknown> {
  if (
    checkpoint.signatures.some(
      (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "invitation_redeem_authority",
    )
  ) {
    const coveredHead = checkpoint.payload.covered_event_head as
      | Record<string, unknown>
      | undefined;
    if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
    const authorityEvents = [...authoritySeedEvents, ...events].sort(
      (left, right) =>
        numberField(left.payload.sequence, "event_sequence_invalid") -
        numberField(right.payload.sequence, "event_sequence_invalid"),
    );
    const redeemEvent = authorityEvents.find(
      (event) =>
        eventHash(event) === coveredHead.head_hash &&
        (event.payload.event_type === "workspace_invitation_redeemed" ||
          event.payload.event_type === "guest_invitation_redeemed"),
    );
    if (redeemEvent) {
      return invitationRedeemAuthorityPayloadForEvent(
        previousPayload,
        redeemEvent,
        authorityEvents,
      );
    }
    let replayPayload = applyAuthoritySeedEventsToCheckpointPayload(
      previousPayload,
      authoritySeedEvents,
    );
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index]!;
      const nextEvent = events[index + 1];
      if (
        numberField(event.payload.sequence, "event_sequence_invalid") >
        numberField(coveredHead.head_sequence, "event_head_sequence_invalid")
      ) {
        break;
      }
      if (eventHash(event) === coveredHead.head_hash) {
        return eventSignatureAuthorityPayload(event, replayPayload, checkpoint.payload);
      }
      replayPayload = applyEventToCheckpointPayload(replayPayload, event, checkpoint.payload, {
        allowInactiveWrapPrincipal: isInvitationAdmissionWrapEvent(event, nextEvent),
      });
    }
    return previousPayload;
  }

  return checkpoint.signatures.some(
    (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "share_participant_device",
  )
    ? checkpoint.payload
    : previousPayload;
}

export function assertShareParticipantCheckpointAdvance(
  candidate: SignedKeyDirectoryEnvelope,
  events: SignedKeyDirectoryEnvelope[],
  previousPayload: Record<string, unknown>,
): void {
  if (
    candidate.signatures.some(
      (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "device",
    )
  ) {
    return;
  }

  const checkpointSigner = candidate.signatures.find(
    (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "share_participant_device",
  )?.signer;
  if (!checkpointSigner) return;

  if (events.length === 0) {
    throw new Error("share_participant_checkpoint_scope_invalid");
  }

  for (const event of events) {
    if (
      event.payload.event_type !== "document_update_accepted" &&
      event.payload.event_type !== "document_snapshot_accepted"
    ) {
      const deviceSigned = event.signatures.some(
        (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "device",
      );
      const shareParticipantSigned = event.signatures.some(
        (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "share_participant_device",
      );
      if (!deviceSigned || shareParticipantSigned) {
        throw new Error("share_participant_checkpoint_event_invalid");
      }
      continue;
    }

    const eventSigner = event.signatures.find(
      (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "share_participant_device",
    )?.signer;
    if (!eventSigner) throw new Error("share_participant_checkpoint_signer_missing");

    for (const key of [
      "share_id",
      "share_participant_principal_id",
      "share_participant_device_id",
      "signing_key_id",
    ]) {
      if (eventSigner[key] !== checkpointSigner[key]) {
        throw new Error("share_participant_checkpoint_signer_mismatch");
      }
    }
  }

  const candidatePayload = candidate.payload;
  for (const key of ["identity_keys", "device_keys", "revoked_key_ids"]) {
    if (!sameCheckpointStateEntries(candidatePayload[key], previousPayload[key])) {
      throw new Error("share_participant_checkpoint_state_advanced");
    }
  }

  const signingKeyId = stringField(checkpointSigner.signing_key_id, "signing_key_id_invalid");
  const previousShareParticipantKeys = arrayField(previousPayload.share_participant_keys);
  const candidateShareParticipantKeys = arrayField(candidatePayload.share_participant_keys);
  const alreadyAdmitted = previousShareParticipantKeys.some(
    (entry) => isRecord(entry) && entry.key_id === signingKeyId,
  );

  const expectedShareParticipantKeys = alreadyAdmitted
    ? previousShareParticipantKeys
    : [
        ...previousShareParticipantKeys,
        shareParticipantKeyEntryById(candidatePayload, signingKeyId),
      ];

  if (!sameCheckpointStateEntries(candidateShareParticipantKeys, expectedShareParticipantKeys)) {
    throw new Error("share_participant_checkpoint_state_advanced");
  }
}

export async function verifyEventSignatures(
  event: SignedKeyDirectoryEnvelope,
  checkpointPayload: Record<string, unknown>,
  options: { allowInactiveSigner?: boolean } = {},
): Promise<void> {
  const signingKeys = signingKeyMaterialById(checkpointPayload);
  for (const signatureEnvelope of event.signatures) {
    const signer = signatureEnvelope.signer;
    const signingKeyId = stringField(signer.signing_key_id, "signing_key_id_invalid");
    const material = signingKeys.get(signingKeyId);
    if (!material) throw new Error("key_directory_event_signer_unknown");
    assertSignerMatchesMaterial(signer, material);
    assertActorMatchesSigner(event.payload.actor as Record<string, unknown>, signer);
    if (!options.allowInactiveSigner) {
      assertKeyEntryActiveAtSequence(
        checkpointPayload,
        signingKeyId,
        numberField(event.payload.sequence, "event_sequence_invalid"),
      );
    }
    const valid = await getCryptoWorker().verifyKeyDirectoryEventSignature({
      eventType: stringField(event.payload.event_type, "event_type_invalid") as never,
      eventPayload: event.payload as StrictJsonValue,
      signature: signatureEnvelope.signature as HybridSignature,
      publicKeyMaterial: material,
    });
    if (!valid) throw new Error("key_directory_event_signature_invalid");
  }
}
