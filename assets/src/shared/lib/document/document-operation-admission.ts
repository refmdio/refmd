import {
  assertEnvelope,
  checkpointHash,
  eventHash,
  isRecord,
  numberField,
  stringField,
} from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  lookupVerifiedKeyDirectoryLineage,
  rememberVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  pinFromCheckpoint,
  verifyCheckpointAncestry,
  verifyCheckpointSignatures,
  verifyEventAncestry,
} from "@/shared/lib/anti-rollback/key-directory-pin/verification";
import { verifyEventSignatures } from "@/shared/lib/anti-rollback/key-directory-pin/signatures";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { DocumentOperationAdmission } from "@/shared/lib/ws/document-payloads";

export type DocumentOperationEventType = "document_update_accepted" | "document_snapshot_accepted";

export interface DocumentOperationAuthorityBoundary {
  [key: string]: unknown;
  previous_workspace_event_sequence: number;
  previous_workspace_event_hash: string;
  admission_event_type: DocumentOperationEventType;
  admission_nonce: string;
  min_dek_version: number;
  document_permission_proof_hash: string;
}

export function documentOperationAuthorityBoundary(
  admission: DocumentOperationAdmission,
  eventType: DocumentOperationEventType,
): DocumentOperationAuthorityBoundary {
  const event = documentOperationEvent(admission, eventType);
  const body = event.payload.body;

  return {
    previous_workspace_event_sequence: numberField(
      body.previous_workspace_event_sequence,
      "previous_workspace_event_sequence_invalid",
    ),
    previous_workspace_event_hash: stringField(
      body.previous_workspace_event_hash,
      "previous_workspace_event_hash_invalid",
    ),
    admission_event_type: eventType,
    admission_nonce: stringField(body.admission_nonce, "admission_nonce_invalid"),
    min_dek_version: numberField(body.min_dek_version, "min_dek_version_invalid"),
    document_permission_proof_hash: stringField(
      body.document_permission_proof_hash,
      "document_permission_proof_hash_invalid",
    ),
  };
}

export async function verifyDocumentOperationAdmission(params: {
  admission: DocumentOperationAdmission;
  eventType: DocumentOperationEventType;
  publicData: object;
  workspaceId: string;
  documentId: string;
  operationHash: string;
  signature: unknown;
  actorUserId: string;
  expectedAdmissionEventHash?: string;
}): Promise<void> {
  const publicData = params.publicData as Record<string, unknown>;
  const event = documentOperationEvent(params.admission, params.eventType);
  const checkpoint = assertEnvelope(params.admission.workspaceKeyDirectoryCheckpoint);
  const payload = event.payload;
  const body = payload.body;
  const checkpointPayload = checkpoint.payload;
  const coveredHead = checkpointPayload.covered_event_head;
  if (!isRecord(coveredHead)) throw new Error("document_admission_checkpoint_head_invalid");

  const publicCheckpointSequence = numberField(
    publicData.keyCheckpointSequence,
    "key_checkpoint_sequence_invalid",
  );
  const publicCheckpointHash = stringField(
    publicData.keyCheckpointHash,
    "key_checkpoint_hash_invalid",
  );
  const keyVersion = numberField(publicData.keyVersion, "key_version_invalid");
  const admissionEventHash = eventHash(event);

  expect(payload.scope_kind, "workspace", "document_admission_scope_kind_mismatch");
  expect(payload.scope_id, params.workspaceId, "document_admission_scope_id_mismatch");
  expect(payload.event_type, params.eventType, "document_admission_event_type_mismatch");
  expect(body.event_type, params.eventType, "document_admission_body_event_type_mismatch");
  expect(body.workspace_id, params.workspaceId, "document_admission_workspace_id_mismatch");
  expect(body.document_id, params.documentId, "document_admission_document_id_mismatch");
  expect(body.operation_hash, params.operationHash, "document_admission_operation_hash_mismatch");
  expect(
    body.operation_signature_hash,
    blake3Base64Url(canonicalizeStrictBytes(params.signature as StrictJsonValue)),
    "document_admission_signature_hash_mismatch",
  );
  expect(body.dek_version, keyVersion, "document_admission_dek_version_mismatch");
  if (numberField(body.min_dek_version, "min_dek_version_invalid") > keyVersion) {
    throw new Error("document_admission_min_dek_version_mismatch");
  }
  expect(
    body.actor_hash,
    blake3Base64Url(canonicalizeStrictBytes(payload.actor as StrictJsonValue)),
    "document_admission_actor_hash_mismatch",
  );
  expect(
    body.document_permission_proof_hash,
    permissionProofHash(publicData, params.workspaceId, params.documentId),
    "document_admission_permission_proof_mismatch",
  );

  const previousEventSequence = numberField(
    body.previous_workspace_event_sequence,
    "previous_workspace_event_sequence_invalid",
  );
  const eventSequence = numberField(payload.sequence, "event_sequence_invalid");
  expect(eventSequence, previousEventSequence + 1, "document_admission_event_sequence_mismatch");
  expect(
    payload.previous_event_hash,
    body.previous_workspace_event_hash,
    "document_admission_previous_event_hash_mismatch",
  );

  expect(
    numberField(checkpointPayload.sequence, "checkpoint_sequence_invalid"),
    publicCheckpointSequence + 1,
    "document_admission_checkpoint_sequence_mismatch",
  );
  expect(
    checkpointPayload.previous_checkpoint_hash,
    publicCheckpointHash,
    "document_admission_checkpoint_previous_hash_mismatch",
  );
  expect(
    coveredHead.head_sequence,
    eventSequence,
    "document_admission_checkpoint_head_sequence_mismatch",
  );
  expect(
    coveredHead.head_hash,
    admissionEventHash,
    "document_admission_checkpoint_head_hash_mismatch",
  );
  if (params.expectedAdmissionEventHash) {
    expect(
      params.expectedAdmissionEventHash,
      admissionEventHash,
      "document_admission_event_hash_mismatch",
    );
  }
  if (checkpointHash(checkpoint) === publicCheckpointHash) {
    throw new Error("document_admission_checkpoint_not_advanced");
  }

  verifyActor(payload.actor, publicData, params.actorUserId);
  await verifyEventSignatures(event, checkpointPayload);
  await verifyCheckpointSignatures(checkpoint, checkpointPayload);
}

export async function verifyDocumentOperationAdmissionAncestry(params: {
  admission: DocumentOperationAdmission;
  workspaceId: string;
}): Promise<void> {
  const current = await getKeyDirectoryPin("workspace", params.workspaceId);
  if (!current) throw new Error("key_directory_pin_required");

  const candidate = assertEnvelope(params.admission.workspaceKeyDirectoryCheckpoint);
  const candidatePin = pinFromCheckpoint("workspace", params.workspaceId, candidate);
  const checkpoints = checkpointAncestry(params.admission);
  const events = eventAncestry(params.admission);
  const cachedLineage = lookupVerifiedKeyDirectoryLineage("workspace", params.workspaceId, current);
  const authorityEvents = sortUniqueEvents([...(cachedLineage?.events ?? []), ...events]);

  if (
    candidatePin.checkpointSequence > current.checkpointSequence ||
    candidatePin.eventHeadSequence > current.eventHeadSequence
  ) {
    const checkpointAncestryForAdvance = checkpoints.filter((checkpoint) => {
      const sequence = numberField(checkpoint.payload.sequence, "checkpoint_sequence_invalid");
      return sequence >= current.checkpointSequence && sequence < candidatePin.checkpointSequence;
    });
    const eventAncestryForAdvance = events.filter((event) => {
      const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
      return sequence > current.eventHeadSequence && sequence <= candidatePin.eventHeadSequence;
    });
    try {
      await advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: params.workspaceId,
        checkpointEnvelope: params.admission.workspaceKeyDirectoryCheckpoint,
        checkpointAncestry: checkpointAncestryForAdvance.map(envelopeRecord),
        eventAncestry: eventAncestryForAdvance.map(envelopeRecord),
        authorityEventAncestry: authorityEvents.map(envelopeRecord),
      });
    } catch (error) {
      if (error instanceof Error && error.message === "key_directory_pin_conflict") {
        const refreshed = await getKeyDirectoryPin("workspace", params.workspaceId);
        if (
          refreshed &&
          refreshed.checkpointSequence === candidatePin.checkpointSequence &&
          refreshed.checkpointHash === candidatePin.checkpointHash &&
          refreshed.eventHeadSequence === candidatePin.eventHeadSequence &&
          refreshed.eventHeadHash === candidatePin.eventHeadHash
        ) {
          rememberVerifiedAdmissionLineage(params.workspaceId, candidate, checkpoints, events);
          return;
        }
        return verifyDocumentOperationAdmissionAncestry(params);
      }
      throw error;
    }
    rememberVerifiedAdmissionLineage(params.workspaceId, candidate, checkpoints, events);
    return;
  }

  if (
    candidatePin.checkpointSequence === current.checkpointSequence &&
    candidatePin.checkpointHash === current.checkpointHash &&
    candidatePin.eventHeadSequence === current.eventHeadSequence &&
    candidatePin.eventHeadHash === current.eventHeadHash
  ) {
    rememberVerifiedAdmissionLineage(params.workspaceId, candidate, checkpoints, events);
    return;
  }

  const lineageCheckpoints = sortUniqueCheckpoints([
    ...(cachedLineage?.checkpoints ?? []),
    ...checkpoints,
    candidate,
  ]);
  const lineageEvents = sortUniqueEvents([...(cachedLineage?.events ?? []), ...events]);
  const candidateInLineage = lineageCheckpoints.find((checkpoint) => {
    const sequence = numberField(checkpoint.payload.sequence, "checkpoint_sequence_invalid");
    return (
      sequence === candidatePin.checkpointSequence &&
      checkpointHash(checkpoint) === candidatePin.checkpointHash
    );
  });
  if (!candidateInLineage) throw new Error("document_admission_candidate_checkpoint_missing");

  const currentCheckpoint = lineageCheckpoints.find((checkpoint) => {
    const sequence = numberField(checkpoint.payload.sequence, "checkpoint_sequence_invalid");
    return (
      sequence === current.checkpointSequence &&
      checkpointHash(checkpoint) === current.checkpointHash
    );
  });
  if (!currentCheckpoint) throw new Error("document_admission_current_checkpoint_missing");

  const checkpointsFromCandidate = [
    candidate,
    ...lineageCheckpoints.filter((checkpoint) => {
      const sequence = numberField(checkpoint.payload.sequence, "checkpoint_sequence_invalid");
      return sequence > candidatePin.checkpointSequence && sequence < current.checkpointSequence;
    }),
  ];
  const eventsFromCandidate = lineageEvents.filter((event) => {
    const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
    return sequence > candidatePin.eventHeadSequence && sequence <= current.eventHeadSequence;
  });
  const authorityEventsFromCandidate = lineageEvents.filter((event) => {
    const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
    return sequence <= candidatePin.eventHeadSequence;
  });

  await verifyCheckpointAncestry(
    "workspace",
    params.workspaceId,
    candidatePin,
    checkpointsFromCandidate,
    currentCheckpoint,
    eventsFromCandidate,
    authorityEventsFromCandidate,
  );
  await verifyEventAncestry(
    "workspace",
    params.workspaceId,
    candidatePin,
    eventsFromCandidate,
    currentCheckpoint,
    candidate.payload,
    authorityEventsFromCandidate,
  );
  rememberVerifiedAdmissionLineage(
    params.workspaceId,
    currentCheckpoint,
    lineageCheckpoints,
    lineageEvents,
  );
}

function envelopeRecord(envelope: SignedKeyDirectoryEnvelope): Record<string, unknown> {
  return envelope as unknown as Record<string, unknown>;
}

function rememberVerifiedAdmissionLineage(
  workspaceId: string,
  candidate: SignedKeyDirectoryEnvelope,
  checkpoints: SignedKeyDirectoryEnvelope[],
  events: SignedKeyDirectoryEnvelope[],
): void {
  rememberVerifiedKeyDirectoryLineage({
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointEnvelope: candidate,
    checkpointAncestry: checkpoints,
    eventAncestry: events,
  });
}

function checkpointLineageKey(checkpoint: SignedKeyDirectoryEnvelope): string {
  return `${numberField(checkpoint.payload.sequence, "checkpoint_sequence_invalid")}:${checkpointHash(checkpoint)}`;
}

function eventLineageKey(event: SignedKeyDirectoryEnvelope): string {
  return `${numberField(event.payload.sequence, "event_sequence_invalid")}:${eventHash(event)}`;
}

function sortUniqueCheckpoints(
  checkpoints: SignedKeyDirectoryEnvelope[],
): SignedKeyDirectoryEnvelope[] {
  return [
    ...new Map(
      checkpoints.map((checkpoint) => [checkpointLineageKey(checkpoint), checkpoint]),
    ).values(),
  ].sort(
    (a, b) =>
      numberField(a.payload.sequence, "checkpoint_sequence_invalid") -
      numberField(b.payload.sequence, "checkpoint_sequence_invalid"),
  );
}

function sortUniqueEvents(events: SignedKeyDirectoryEnvelope[]): SignedKeyDirectoryEnvelope[] {
  return [...new Map(events.map((event) => [eventLineageKey(event), event])).values()].sort(
    (a, b) =>
      numberField(a.payload.sequence, "event_sequence_invalid") -
      numberField(b.payload.sequence, "event_sequence_invalid"),
  );
}

function documentOperationEvent(
  admission: DocumentOperationAdmission,
  eventType: DocumentOperationEventType,
) {
  const event = admission.workspaceKeyDirectoryEvents
    .map((envelope) => assertEnvelope(envelope))
    .find((envelope) => envelope.payload.event_type === eventType);
  if (!event) throw new Error("document_admission_event_missing");
  if (!isRecord(event.payload.body)) throw new Error("document_admission_body_invalid");
  return event as ReturnType<typeof assertEnvelope> & {
    payload: { body: Record<string, unknown> };
  };
}

function checkpointAncestry(admission: DocumentOperationAdmission): SignedKeyDirectoryEnvelope[] {
  const ancestry = admission.workspaceKeyDirectoryCheckpointAncestry;
  if (!Array.isArray(ancestry)) throw new Error("document_admission_checkpoint_ancestry_missing");
  return ancestry.map((envelope) => assertEnvelope(envelope));
}

function eventAncestry(admission: DocumentOperationAdmission): SignedKeyDirectoryEnvelope[] {
  const ancestry = admission.workspaceKeyDirectoryEventAncestry;
  if (!Array.isArray(ancestry)) throw new Error("document_admission_event_ancestry_missing");
  return ancestry.map((envelope) => assertEnvelope(envelope));
}

function permissionProofHash(
  publicData: Record<string, unknown>,
  workspaceId: string,
  documentId: string,
): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.document-permission-proof",
      version: 1,
      workspace_id: workspaceId,
      document_id: documentId,
      authority_kind: publicData.authorityKind,
      authority_id: publicData.authorityId,
      authority_context_key: publicData.authorityContextKey,
      authority_scope_id: stringField(publicData.authorityScopeId, "authority_scope_id_invalid"),
      authority_permission_version: numberField(
        publicData.authorityPermissionVersion,
        "authority_permission_version_invalid",
      ),
      permission: "edit",
    } as StrictJsonValue),
  );
}

function verifyActor(
  actor: unknown,
  publicData: Record<string, unknown>,
  actorUserId: string,
): void {
  if (!isRecord(actor)) throw new Error("document_admission_actor_invalid");
  const ownerKind = stringField(publicData.ownerKind, "owner_kind_invalid");
  expect(
    publicData.ownerId,
    actorOwnerId(actor, ownerKind),
    "document_admission_actor_owner_mismatch",
  );
  expect(
    actor.signing_key_id,
    publicData.signingKeyId,
    "document_admission_actor_signing_key_mismatch",
  );

  if (ownerKind === "device") {
    expect(actor.signer_kind, "device", "document_admission_actor_kind_mismatch");
    expect(actor.user_id, actorUserId, "document_admission_actor_user_mismatch");
    return;
  }

  if (ownerKind === "share_participant_device") {
    expect(actor.signer_kind, "share_participant_device", "document_admission_actor_kind_mismatch");
    const [_shareId, principalId] = stringField(
      publicData.authorityContextKey,
      "authority_context_key_invalid",
    ).split(":");
    expect(
      actor.share_participant_principal_id,
      principalId,
      "document_admission_actor_principal_mismatch",
    );
    return;
  }

  throw new Error("document_admission_owner_kind_invalid");
}

function actorOwnerId(actor: Record<string, unknown>, ownerKind: string): unknown {
  return ownerKind === "share_participant_device"
    ? actor.share_participant_device_id
    : actor.device_id;
}

function expect(actual: unknown, expected: unknown, error: string): void {
  if (actual !== expected) throw new Error(error);
}
