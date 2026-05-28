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
  keyEntries,
  numberField,
  shareParticipantDeviceActor,
  signCheckpoint,
  signEvent,
  stringField,
} from "./primitives";
import type {
  DocumentAdmissionKeyDirectoryAppendInput,
  DocumentWriteStateKeyDirectoryAppendInput,
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
    body:
      input.eventType === "document_write_session_admitted"
        ? writeSessionBody(
            input,
            actor,
            previousHash,
            previousSequence,
            shareParticipant,
            shareScope,
          )
        : operationAdmissionBody(
            input,
            actor,
            previousHash,
            previousSequence,
            shareParticipant,
            shareScope,
          ),
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

export async function buildDocumentWriteStateKeyDirectoryAppend(
  input: DocumentWriteStateKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  if (input.changes.length === 0) throw new Error("document_write_state_changes_required");

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

  let previousSequence = numberField(coveredHead.head_sequence);
  let previousHash = stringField(coveredHead.head_hash);
  const signedEvents = [];
  let lastEvent: Record<string, unknown> | undefined;

  for (const change of input.changes) {
    const event = keyDirectoryEvent({
      scopeKind: "workspace",
      scopeId: input.workspaceId,
      sequence: previousSequence + 1,
      eventType: "document_write_state_changed",
      actor,
      previousEventHash: previousHash,
      body: {
        document_id: change.documentId,
        event_type: "document_write_state_changed",
        issued_at_ms: Date.now(),
        previous_workspace_event_hash: previousHash,
        previous_workspace_event_sequence: previousSequence,
        previous_write_state: change.previousWriteState,
        reason: input.reason,
        workspace_id: input.workspaceId,
        write_state: change.writeState,
      },
    });

    signedEvents.push(await signEvent("device", event));
    previousSequence = numberField(event.sequence);
    previousHash = eventHash(event);
    lastEvent = event;
  }

  if (!lastEvent) throw new Error("document_write_state_changes_required");

  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(lastEvent),
    identityKeys: keyEntries(checkpointPayload, "identity_keys"),
    deviceKeys: keyEntries(checkpointPayload, "device_keys"),
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint("device", "workspace_authorized", checkpoint);
  return { events: signedEvents, checkpoint: signedCheckpoint };
}

function operationAdmissionBody(
  input: DocumentAdmissionKeyDirectoryAppendInput,
  actor: StrictJsonValue,
  previousHash: string,
  previousSequence: number,
  shareParticipant: boolean,
  shareScope: { shareId: string; shareSessionId: string } | undefined,
): Record<string, unknown> {
  if (!input.operationHash || !input.operationSignatureHash || input.dekVersion === undefined) {
    throw new Error("document_operation_admission_input_invalid");
  }
  return {
    actor_hash: blake3Base64Url(canonicalizeStrictBytes(actor)),
    admission_nonce: requireString(input.admissionNonce, "admission_nonce_invalid"),
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
  };
}

function writeSessionBody(
  input: DocumentAdmissionKeyDirectoryAppendInput,
  actor: StrictJsonValue,
  previousHash: string,
  previousSequence: number,
  shareParticipant: boolean,
  shareScope: { shareId: string; shareSessionId: string } | undefined,
): Record<string, unknown> {
  const participantScope = shareParticipant
    ? requireShareParticipantScope(input.shareId, input.shareSessionId)
    : undefined;

  return {
    actor_hash: blake3Base64Url(canonicalizeStrictBytes(actor)),
    authority_kind: shareParticipant ? "share_participant_device" : "workspace_device",
    authority_scope_id: participantScope ? participantScope.shareId : input.workspaceId,
    document_id: input.documentId,
    document_permission_proof_hash: input.documentPermissionProofHash,
    event_type: "document_write_session_admitted",
    expires_at_ms: requireNumber(input.expiresAtMs, "expires_at_ms_invalid"),
    issued_at_ms: requireNumber(input.issuedAtMs, "issued_at_ms_invalid"),
    max_ciphertext_bytes: requireNumber(input.maxCiphertextBytes, "max_ciphertext_bytes_invalid"),
    max_update_count: requireNumber(input.maxUpdateCount, "max_update_count_invalid"),
    min_dek_version: requireNumber(input.minDekVersion, "min_dek_version_invalid"),
    previous_workspace_event_hash: previousHash,
    previous_workspace_event_sequence: previousSequence,
    session_id: requireString(input.sessionId, "write_session_id_invalid"),
    session_nonce: requireString(input.sessionNonce, "write_session_nonce_invalid"),
    ...(shareParticipant ? shareAdmissionScopeFields(shareScope) : {}),
    workspace_id: input.workspaceId,
  };
}

function requireString(value: string | undefined, code: string): string {
  if (!value) throw new Error(code);
  return value;
}

function requireNumber(value: number | undefined, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error(code);
  return value;
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
