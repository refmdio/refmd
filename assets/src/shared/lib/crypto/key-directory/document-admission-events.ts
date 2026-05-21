import { blake3Base64Url } from "../hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import {
  activeDeviceSigningKeyId,
  actorWithCheckpointAuthority,
  checkpointShareParticipantKeys,
  deviceActor,
  eventHash,
  eventHead,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  keyEntry,
  numberField,
  shareParticipantDeviceActor,
  signCheckpoint,
  signEvent,
  stringField,
} from "./primitives";
import type {
  DocumentAdmissionKeyDirectoryAppendInput,
  KeyDirectoryAppendArtifacts,
} from "./types";

export async function buildDocumentAdmissionKeyDirectoryAppend(
  input: DocumentAdmissionKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");

  const previousSequence = numberField(coveredHead.head_sequence);
  const previousHash = stringField(coveredHead.head_hash);
  const actorInput = input.actor;
  const shareParticipant = actorInput.kind === "share_participant_device";
  let shareScope: { shareId: string; shareSessionId: string } | undefined;
  const actor = shareParticipant
    ? (() => {
        shareScope = requireShareParticipantScope(input.shareId, input.shareSessionId);
        return actorWithCheckpointAuthority(
          shareParticipantDeviceActor(
            shareScope.shareId,
            actorInput.principalId,
            actorInput.deviceId,
            actorInput.signingKeyId,
          ),
          "workspace",
          input.workspaceId,
          checkpointPayload,
        );
      })()
    : actorWithCheckpointAuthority(
        deviceActor(
          actorInput.userId,
          actorInput.deviceId,
          activeDeviceSigningKeyId(checkpointPayload, actorInput.deviceId),
        ),
        "workspace",
        input.workspaceId,
        checkpointPayload,
      );
  const shareParticipantKeyAlreadyAdmitted =
    shareParticipant &&
    checkpointShareParticipantKeys(checkpointPayload).some(
      (entry) => entry.key_id === actorInput.signingKeyId,
    );

  const event = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: previousSequence + 1,
    eventType: input.eventType,
    actor,
    previousEventHash: previousHash,
    body: {
      actor_hash: blake3Base64Url(canonicalizeStrictBytes(actor)),
      admission_nonce: input.admissionNonce,
      dek_version: input.dekVersion,
      document_id: input.documentId,
      document_permission_proof_hash: input.documentPermissionProofHash,
      event_type: input.eventType,
      min_dek_version: input.minDekVersion,
      operation_hash: input.operationHash,
      operation_signature_hash: input.operationSignatureHash,
      previous_workspace_event_hash: previousHash,
      previous_workspace_event_sequence: previousSequence,
      ...(shareParticipant ? shareAdmissionScopeFields(shareScope) : {}),
      workspace_id: input.workspaceId,
    },
  });

  const signedEvent = await signEvent(
    shareParticipant ? "share_participant_device" : "device",
    event,
    input.shareSlug,
    shareScope?.shareId,
  );
  const events = [signedEvent];
  const shareParticipantKeys =
    shareParticipant && !shareParticipantKeyAlreadyAdmitted
      ? [
          ...checkpointShareParticipantKeys(checkpointPayload),
          keyEntry(actorInput.signingKeyId, actorInput.hybridSigningPublicKeyMaterial, {
            scope_kind: "workspace",
            scope_id: input.workspaceId,
            event_sequence: numberField(event.sequence),
            event_hash: eventHash(event),
          }),
        ]
      : checkpointShareParticipantKeys(checkpointPayload);
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
  const signedCheckpoint = await signCheckpoint(
    shareParticipant ? "share_participant_device" : "device",
    shareParticipant ? "share_participant_document_operation" : "workspace_authorized",
    checkpoint,
    input.shareSlug,
    shareScope?.shareId,
  );
  return { events, checkpoint: signedCheckpoint };
}

function requireShareParticipantScope(
  shareId: string | undefined,
  shareSessionId: string | undefined,
): { shareId: string; shareSessionId: string } {
  if (!shareId || !shareSessionId) {
    throw new Error("share_participant_admission_scope_missing");
  }
  return { shareId, shareSessionId };
}

function shareAdmissionScopeFields(
  scope: { shareId: string; shareSessionId: string } | undefined,
): Record<string, string> {
  if (!scope) throw new Error("share_participant_admission_scope_missing");

  return {
    share_id: scope.shareId,
    share_session_id: scope.shareSessionId,
    share_permission: "edit",
    share_authority_kind: "share_participant_device",
  };
}
