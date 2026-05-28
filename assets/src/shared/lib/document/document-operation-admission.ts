import {
  assertEnvelope,
  checkpointHash,
  eventHash,
  isRecord,
  numberField,
  stringField,
} from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import { documentsApi } from "@/shared/api/documents";
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
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

export type DocumentOperationEventType =
  | "document_update_accepted"
  | "document_snapshot_accepted"
  | "document_write_session_admitted";

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

export function documentWriteSessionAuthorityBoundaryForDocument(params: {
  publicData: object;
  workspaceId: string;
  documentId: string;
}) {
  const data = params.publicData as Record<string, unknown>;
  return {
    write_session_event_hash: stringField(
      data.writeSessionEventHash,
      "write_session_event_hash_invalid",
    ),
    write_session_id: stringField(data.writeSessionId, "write_session_id_invalid"),
    write_session_counter: numberField(data.writeSessionCounter, "write_session_counter_invalid"),
    min_dek_version: numberField(data.minDekVersion, "min_dek_version_invalid"),
    document_permission_proof_hash: permissionProofHash(
      data,
      params.workspaceId,
      params.documentId,
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
  if (!isRecord(body)) throw new Error("document_admission_body_invalid");
  assertOperationAdmissionBody(body);

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

export async function verifyDocumentWriteSessionAdmission(params: {
  admission: DocumentOperationAdmission;
  publicData: object;
  workspaceId: string;
  documentId: string;
  actorUserId: string;
}): Promise<void> {
  const eventType = "document_write_session_admitted";
  const publicData = params.publicData as Record<string, unknown>;
  const event = documentOperationEvent(params.admission, eventType);
  const checkpoint = assertEnvelope(params.admission.workspaceKeyDirectoryCheckpoint);
  const payload = event.payload;
  const body = payload.body;
  const checkpointPayload = checkpoint.payload;
  const coveredHead = checkpointPayload.covered_event_head;
  if (!isRecord(coveredHead)) throw new Error("document_admission_checkpoint_head_invalid");
  if (!isRecord(body)) throw new Error("document_admission_body_invalid");
  assertWriteSessionBody(body);

  const publicCheckpointSequence = numberField(
    publicData.keyCheckpointSequence,
    "key_checkpoint_sequence_invalid",
  );
  const publicCheckpointHash = stringField(
    publicData.keyCheckpointHash,
    "key_checkpoint_hash_invalid",
  );
  const keyVersion = numberField(publicData.keyVersion, "key_version_invalid");
  const minDekVersion = numberField(publicData.minDekVersion, "min_dek_version_invalid");
  const authorityKind = stringField(publicData.authorityKind, "authority_kind_invalid");
  const authorityScopeId = stringField(publicData.authorityScopeId, "authority_scope_id_invalid");
  const admissionEventHash = eventHash(event);
  const writeSessionCounter = numberField(
    publicData.writeSessionCounter,
    "write_session_counter_invalid",
  );
  const maxUpdateCount = numberField(body.max_update_count, "max_update_count_invalid");
  const issuedAtMs = numberField(body.issued_at_ms, "issued_at_ms_invalid");
  const expiresAtMs = numberField(body.expires_at_ms, "expires_at_ms_invalid");

  expect(payload.scope_kind, "workspace", "document_admission_scope_kind_mismatch");
  expect(payload.scope_id, params.workspaceId, "document_admission_scope_id_mismatch");
  expect(payload.event_type, eventType, "document_admission_event_type_mismatch");
  expect(body.event_type, eventType, "document_admission_body_event_type_mismatch");
  expect(body.workspace_id, params.workspaceId, "document_admission_workspace_id_mismatch");
  expect(body.document_id, params.documentId, "document_admission_document_id_mismatch");
  expect(body.min_dek_version, minDekVersion, "document_admission_min_dek_version_mismatch");
  expect(body.authority_kind, authorityKind, "document_admission_authority_kind_mismatch");
  expect(body.authority_scope_id, authorityScopeId, "document_admission_authority_scope_mismatch");
  stringField(body.session_nonce, "write_session_nonce_invalid");
  if (minDekVersion > keyVersion) throw new Error("document_admission_min_dek_version_mismatch");
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
  expect(
    body.session_id,
    publicData.writeSessionId,
    "document_admission_write_session_id_mismatch",
  );
  expect(
    publicData.writeSessionEventHash,
    admissionEventHash,
    "document_admission_event_hash_mismatch",
  );
  if (!Number.isSafeInteger(writeSessionCounter) || writeSessionCounter < 1) {
    throw new Error("document_admission_write_session_counter_invalid");
  }
  if (!Number.isSafeInteger(maxUpdateCount) || writeSessionCounter > maxUpdateCount) {
    throw new Error("document_admission_write_session_counter_exceeded");
  }
  if (
    !Number.isSafeInteger(issuedAtMs) ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= issuedAtMs ||
    expiresAtMs - issuedAtMs > 60_000
  ) {
    throw new Error("document_admission_write_session_lifetime_invalid");
  }

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
  if (checkpointHash(checkpoint) === publicCheckpointHash) {
    throw new Error("document_admission_checkpoint_not_advanced");
  }

  verifyActor(payload.actor, publicData, params.actorUserId);
  await verifyEventSignatures(event, checkpointPayload);
  await verifyCheckpointSignatures(checkpoint, checkpointPayload);
}

const WRITE_SESSION_BODY_KEYS = [
  "actor_hash",
  "authority_kind",
  "authority_scope_id",
  "document_id",
  "document_permission_proof_hash",
  "event_type",
  "expires_at_ms",
  "issued_at_ms",
  "max_ciphertext_bytes",
  "max_update_count",
  "min_dek_version",
  "previous_workspace_event_hash",
  "previous_workspace_event_sequence",
  "session_id",
  "session_nonce",
  "workspace_id",
] as const;

const WRITE_SESSION_SHARE_BODY_KEYS = [
  ...WRITE_SESSION_BODY_KEYS,
  "share_authority_kind",
  "share_id",
  "share_permission",
  "share_session_id",
] as const;

const OPERATION_ADMISSION_BODY_KEYS = [
  "actor_hash",
  "admission_nonce",
  "dek_version",
  "document_id",
  "document_permission_proof_hash",
  "event_type",
  "min_dek_version",
  "operation_hash",
  "operation_signature_hash",
  "previous_workspace_event_hash",
  "previous_workspace_event_sequence",
  "workspace_id",
] as const;

const OPERATION_ADMISSION_SHARE_BODY_KEYS = [
  ...OPERATION_ADMISSION_BODY_KEYS,
  "share_authority_kind",
  "share_id",
  "share_permission",
  "share_session_id",
] as const;

function assertOperationAdmissionBody(body: Record<string, unknown>): void {
  const expectedKeys =
    "share_id" in body ? OPERATION_ADMISSION_SHARE_BODY_KEYS : OPERATION_ADMISSION_BODY_KEYS;
  const actual = Object.keys(body).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expectedKeys].sort())) {
    throw new Error("document_admission_body_keys_invalid");
  }
}

function assertWriteSessionBody(body: Record<string, unknown>): void {
  const expectedKeys = "share_id" in body ? WRITE_SESSION_SHARE_BODY_KEYS : WRITE_SESSION_BODY_KEYS;
  const actual = Object.keys(body).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expectedKeys].sort())) {
    throw new Error("document_admission_body_keys_invalid");
  }
}

export function assertWriteSessionNotInvalidatedByEvents(params: {
  sessionEvent: SignedKeyDirectoryEnvelope;
  publicData: object;
  documentId: string;
  documentAncestorIds?: readonly string[];
  keyVersion: number;
  events: SignedKeyDirectoryEnvelope[];
}): void {
  const publicData = params.publicData as Record<string, unknown>;
  const actor = params.sessionEvent.payload.actor;
  if (!isRecord(actor)) throw new Error("document_admission_actor_invalid");
  const ownerKind = stringField(publicData.ownerKind, "owner_kind_invalid");
  const signingKeyId = stringField(publicData.signingKeyId, "signing_key_id_invalid");

  for (const event of params.events) {
    const body = event.payload.body;
    if (!isRecord(body)) throw new Error("key_directory_event_body_invalid");
    switch (event.payload.event_type) {
      case "signing_key_revoked":
        if (body.key_id === signingKeyId) {
          throw new Error("document_write_session_signing_key_revoked");
        }
        break;
      case "member_removed":
        if (ownerKind === "device" && body.user_id === actor.user_id) {
          throw new Error("document_write_session_actor_removed");
        }
        break;
      case "member_role_changed":
        if (
          ownerKind === "device" &&
          body.user_id === actor.user_id &&
          !baseRoleCanWriteDocument(body.base_role)
        ) {
          throw new Error("document_write_session_actor_write_denied");
        }
        break;
      case "share_revoked":
        if (ownerKind === "share_participant_device" && body.share_id === actor.share_id) {
          throw new Error("document_write_session_share_revoked");
        }
        break;
      case "share_key_scope_removed":
        if (
          ownerKind === "share_participant_device" &&
          body.share_id === actor.share_id &&
          shareScopeRemovalInvalidatesSession(body, params.documentId, params.documentAncestorIds)
        ) {
          throw new Error("document_write_session_share_scope_removed");
        }
        break;
      case "guest_grant_revoked":
        if (
          ownerKind === "share_participant_device" &&
          body.guest_user_id === actor.share_participant_principal_id &&
          guestGrantRevocationInvalidatesSession(
            body,
            actor,
            params.documentId,
            params.documentAncestorIds,
          )
        ) {
          throw new Error("document_write_session_guest_grant_revoked");
        }
        break;
      case "guest_device_revoked":
        if (
          ownerKind === "share_participant_device" &&
          body.guest_user_id === actor.share_participant_principal_id &&
          guestDeviceRevocationInvalidatesSession(body, actor)
        ) {
          throw new Error("document_write_session_guest_device_revoked");
        }
        break;
      case "document_write_state_changed":
        if (documentWriteStateInvalidatesSession(body, params.documentId)) {
          throw new Error("document_write_session_document_state_invalidated");
        }
        break;
      case "rotation_started":
      case "rotation_completed":
        if (dekFloorInvalidatesSession(body, params.documentId, params.keyVersion)) {
          throw new Error("document_write_session_dek_floor_invalidated");
        }
        break;
    }
  }
}

export async function verifyDocumentWriteSessionNotInvalidated(params: {
  admission: DocumentOperationAdmission;
  publicData: object;
  workspaceId: string;
  documentId: string;
  keyVersion: number;
}): Promise<void> {
  const current = await getKeyDirectoryPin("workspace", params.workspaceId);
  if (!current) throw new Error("key_directory_pin_required");

  const sessionEvent = documentOperationEvent(params.admission, "document_write_session_admitted");
  const sessionSequence = numberField(sessionEvent.payload.sequence, "event_sequence_invalid");
  if (current.eventHeadSequence <= sessionSequence) return;

  const cachedLineage = lookupVerifiedKeyDirectoryLineage("workspace", params.workspaceId, current);
  const events = sortUniqueEvents([
    ...(cachedLineage?.events ?? []),
    ...eventAncestry(params.admission),
  ]);
  const replayEvents = events.filter((event) => {
    const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
    return sequence > sessionSequence && sequence <= current.eventHeadSequence;
  });
  const documentAncestorIds = needsShareFolderScopeEvidence({
    sessionEvent,
    publicData: params.publicData,
    events: replayEvents,
  })
    ? await loadDocumentAncestorIds(params.workspaceId, params.documentId)
    : undefined;

  assertWriteSessionNotInvalidatedByEvents({
    sessionEvent,
    publicData: params.publicData,
    documentId: params.documentId,
    documentAncestorIds,
    keyVersion: params.keyVersion,
    events: replayEvents,
  });
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

function baseRoleCanWriteDocument(role: unknown): boolean {
  return role === "owner" || role === "admin" || role === "editor" || role === "guest";
}

function dekFloorInvalidatesSession(
  body: Record<string, unknown>,
  documentId: string,
  keyVersion: number,
): boolean {
  if (body.rotation_kind !== "dek") return false;
  if (body.scope_kind === "document" && body.scope_id !== documentId) return false;
  if (body.scope_kind !== "document" && body.scope_kind !== "workspace") return false;
  return typeof body.new_key_version === "number" && body.new_key_version > keyVersion;
}

function shareScopeRemovalInvalidatesSession(
  body: Record<string, unknown>,
  documentId: string,
  documentAncestorIds?: readonly string[],
): boolean {
  if (body.scope_kind === "document") return body.scope_id === documentId;
  if (body.scope_kind !== "folder") return false;
  const scopeId = body.scope_id;
  if (!isString(scopeId)) return false;
  if (!documentAncestorIds) {
    throw new Error("document_write_session_share_scope_evidence_missing");
  }
  return documentAncestorIds.includes(scopeId);
}

function guestGrantRevocationInvalidatesSession(
  body: Record<string, unknown>,
  actor: Record<string, unknown>,
  documentId: string,
  documentAncestorIds?: readonly string[],
): boolean {
  if (body.scope_kind === "workspace") return true;
  if (body.scope_kind === "share") return body.scope_id === actor.share_id;
  return shareScopeRemovalInvalidatesSession(body, documentId, documentAncestorIds);
}

function guestDeviceRevocationInvalidatesSession(
  body: Record<string, unknown>,
  actor: Record<string, unknown>,
): boolean {
  return (
    body.guest_device_id === actor.share_participant_device_id ||
    body.guest_signing_key_id === actor.signing_key_id
  );
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function needsShareFolderScopeEvidence(params: {
  sessionEvent: SignedKeyDirectoryEnvelope;
  publicData: object;
  events: SignedKeyDirectoryEnvelope[];
}): boolean {
  const publicData = params.publicData as Record<string, unknown>;
  if (publicData.ownerKind !== "share_participant_device") return false;
  const actor = params.sessionEvent.payload.actor;
  if (!isRecord(actor) || !isString(actor.share_id)) return false;

  return params.events.some((event) => {
    const body = event.payload.body;
    return (
      event.payload.event_type === "share_key_scope_removed" &&
      isRecord(body) &&
      body.share_id === actor.share_id &&
      body.scope_kind === "folder"
    );
  });
}

async function loadDocumentAncestorIds(workspaceId: string, documentId: string): Promise<string[]> {
  const response = await documentsApi.list(workspaceId);
  const documents = Array.isArray(response.documents) ? response.documents : [];
  const parentById = new Map<string, string | null>();
  for (const document of documents) {
    if (!isRecord(document) || !isString(document.id)) continue;
    parentById.set(document.id, isString(document.parent_id) ? document.parent_id : null);
  }
  if (!parentById.has(documentId)) {
    throw new Error("document_write_session_share_scope_evidence_missing");
  }

  const ancestors: string[] = [];
  const visited = new Set<string>([documentId]);
  let parentId = parentById.get(documentId) ?? null;
  while (parentId) {
    if (visited.has(parentId)) {
      throw new Error("document_write_session_share_scope_evidence_invalid");
    }
    visited.add(parentId);
    ancestors.push(parentId);
    parentId = parentById.get(parentId) ?? null;
  }
  return ancestors;
}

function documentWriteStateInvalidatesSession(
  body: Record<string, unknown>,
  documentId: string,
): boolean {
  if (!documentStateEventTargetsDocument(body, documentId)) return false;
  return (
    body.write_state === "read_only" ||
    body.write_state === "archived" ||
    body.write_state === "write_disabled"
  );
}

function documentStateEventTargetsDocument(
  body: Record<string, unknown>,
  documentId: string,
): boolean {
  return body.document_id === documentId;
}

export function resolveDocumentWriteSessionSigningKeyFromAdmission(params: {
  admission: DocumentOperationAdmission;
  publicData: object;
}): { key: HybridSigningPublicKeyMaterial; actorUserId: string } | null {
  return resolveDocumentOperationSigningKeyFromAdmission({
    ...params,
    eventType: "document_write_session_admitted",
  });
}

export function resolveDocumentOperationSigningKeyFromAdmission(params: {
  admission: DocumentOperationAdmission;
  eventType: DocumentOperationEventType;
  publicData: object;
}): { key: HybridSigningPublicKeyMaterial; actorUserId: string } | null {
  const publicData = params.publicData as Record<string, unknown>;
  const ownerKind = stringField(publicData.ownerKind, "owner_kind_invalid");
  const ownerId = stringField(publicData.ownerId, "owner_id_invalid");
  const signingKeyId = stringField(publicData.signingKeyId, "signing_key_id_invalid");
  const event = documentOperationEvent(params.admission, params.eventType);
  const actor = event.payload.actor;
  if (!isRecord(actor)) throw new Error("document_admission_actor_invalid");

  const actorUserId =
    ownerKind === "share_participant_device"
      ? stringField(actor.share_participant_principal_id, "share_participant_principal_id_invalid")
      : stringField(actor.user_id, "actor_user_id_invalid");
  verifyActor(actor, publicData, actorUserId);

  const checkpoint = assertEnvelope(params.admission.workspaceKeyDirectoryCheckpoint);
  const payload = checkpoint.payload as Record<string, unknown>;
  const entries =
    ownerKind === "share_participant_device" ? payload.share_participant_keys : payload.device_keys;
  if (!Array.isArray(entries)) return null;

  for (const entry of entries) {
    if (!isRecord(entry)) continue;
    if (entry.revoked_at !== undefined) continue;
    if (entry.key_id !== signingKeyId) continue;
    const material = entry.key_material as HybridSigningPublicKeyMaterial;
    if (
      !material ||
      material.protocol !== "refmd.hybrid-signing-key-material" ||
      material.owner_kind !== ownerKind ||
      material.owner_id !== ownerId
    ) {
      return null;
    }
    return { key: material, actorUserId };
  }

  return null;
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
