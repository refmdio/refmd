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
  numberField,
  signCheckpoint,
  signEvent,
  stringField,
} from "./primitives";
import type {
  DekRotationCompletionKeyDirectoryAppendInput,
  DekRotationStartKeyDirectoryAppendInput,
  KekRotationCompletionKeyDirectoryAppendInput,
  KekRotationStartKeyDirectoryAppendInput,
  KeyDirectoryAppendArtifacts,
  KeyDirectoryEnvelope,
} from "./types";
import { CURRENT_PROTOCOL_VERSION } from "../suite";

export async function buildKekRotationCompletionKeyDirectoryAppend(
  input: KekRotationCompletionKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  if (input.newKeyVersion <= input.oldKeyVersion) throw new Error("kek_rotation_version_invalid");

  const completedSequence = numberField(coveredHead.head_sequence) + 1;
  const completionEvent = kekRotationCompletedEvent({
    ...input,
    completedSequence,
    previousEventHash: stringField(coveredHead.head_hash),
  });
  const deletionEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: completedSequence + 1,
    eventType: "old_key_deleted",
    actor: actorWithCheckpointAuthority(
      deviceActor(
        input.actorUserId,
        input.actorDeviceId,
        activeDeviceSigningKeyId(checkpointPayload, input.actorDeviceId),
      ),
      "workspace",
      input.workspaceId,
      checkpointPayload,
    ),
    previousEventHash: eventHash(completionEvent),
    body: {
      event_type: "old_key_deleted",
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: input.workspaceId,
      old_key_version: input.oldKeyVersion,
      deleted_at_event_sequence: completedSequence + 1,
      deletion_manifest_hash: input.deletionManifestHash,
    },
  });
  const signedEvents = await Promise.all([
    signEvent("device", completionEvent),
    signEvent("device", deletionEvent),
  ]);
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(deletionEvent),
    identityKeys: (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
    deviceKeys: (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint("device", "workspace_authorized", checkpoint);
  return { events: signedEvents, checkpoint: signedCheckpoint };
}

export function kekRotationCompletedEventHash(
  input: Omit<KekRotationCompletionKeyDirectoryAppendInput, "deletionManifestHash">,
): string {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  return eventHash(
    kekRotationCompletedEvent({
      ...input,
      completedSequence: numberField(coveredHead.head_sequence) + 1,
      previousEventHash: stringField(coveredHead.head_hash),
    }),
  );
}

export function buildKekOldKeyDeletionManifestHash(input: {
  workspaceId: string;
  oldKeyVersion: number;
  rotationCompletedEventHash: string;
  deletedSecretIdsHash: string;
  deletedWrapIdsHash: string;
  deviceKeyDeletionProofs: Record<string, unknown>[];
  wipeRequiredDeviceIds: string[];
  serverRejectsOldKeyUploadsAfterSequence: number;
}): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.old-key-deletion-manifest",
      version: CURRENT_PROTOCOL_VERSION,
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: input.workspaceId,
      old_key_version: input.oldKeyVersion,
      rotation_completed_event_hash: input.rotationCompletedEventHash,
      deleted_secret_ids_hash: input.deletedSecretIdsHash,
      deleted_wrap_ids_hash: input.deletedWrapIdsHash,
      active_device_deletion_proofs_hash: activeDeviceDeletionProofsHash(
        input.deviceKeyDeletionProofs,
      ),
      wipe_required_device_ids_hash: wipeRequiredDeviceIdsHash(input.wipeRequiredDeviceIds),
      server_rejects_old_key_uploads_after_sequence: input.serverRejectsOldKeyUploadsAfterSequence,
    }),
  );
}

function kekRotationCompletedEvent(
  input: Omit<KekRotationCompletionKeyDirectoryAppendInput, "deletionManifestHash"> & {
    completedSequence: number;
    previousEventHash: string;
  },
): Record<string, unknown> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
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
  return keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: input.completedSequence,
    eventType: "rotation_completed",
    actor,
    previousEventHash: input.previousEventHash,
    body: {
      event_type: "rotation_completed",
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: input.workspaceId,
      old_key_version: input.oldKeyVersion,
      new_key_version: input.newKeyVersion,
      completed_at_event_sequence: input.completedSequence,
      completion_manifest_hash: input.completionManifestHash,
    },
  });
}

function activeDeviceDeletionProofsHash(proofs: Record<string, unknown>[]): string {
  const proofHashes = proofs
    .map((proof) => {
      const payload = proof.payload;
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        throw new Error("device_key_deletion_proof_payload_invalid");
      }
      return blake3Base64Url(canonicalizeStrictBytes(payload as StrictJsonValue));
    })
    .filter((value, index, values) => values.indexOf(value) === index)
    .sort();

  return blake3Base64Url(canonicalizeStrictBytes({ proof_hashes: proofHashes }));
}

function wipeRequiredDeviceIdsHash(deviceIds: string[]): string {
  const sortedUniqueIds = deviceIds
    .filter((value, index, values) => {
      if (typeof value !== "string" || value.length === 0) {
        throw new Error("wipe_required_device_id_invalid");
      }
      return values.indexOf(value) === index;
    })
    .sort();

  return blake3Base64Url(canonicalizeStrictBytes({ device_ids: sortedUniqueIds }));
}

export async function buildKekRotationStartKeyDirectoryAppend(
  input: KekRotationStartKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  if (input.newKeyVersion <= input.oldKeyVersion) throw new Error("kek_rotation_version_invalid");

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
  const startedSequence = numberField(coveredHead.head_sequence) + 1;
  const startEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: startedSequence,
    eventType: "rotation_started",
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      event_type: "rotation_started",
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: input.workspaceId,
      old_key_version: input.oldKeyVersion,
      new_key_version: input.newKeyVersion,
      not_before_event_sequence: startedSequence,
      reason: input.reason,
    },
  });
  const signedEvent = await signEvent("device", startEvent);
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(startEvent),
    identityKeys: (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
    deviceKeys: (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint("device", "workspace_authorized", checkpoint);
  return { events: [signedEvent], checkpoint: signedCheckpoint };
}

export async function buildDekRotationStartKeyDirectoryAppend(
  input: DekRotationStartKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = checkpointPayloadWithHead(input.checkpointEnvelope);
  if (input.newKeyVersion <= input.oldKeyVersion) throw new Error("dek_rotation_version_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown>;
  const sequence = numberField(coveredHead.head_sequence) + 1;
  const event = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence,
    eventType: "rotation_started",
    actor: rotationActor(input, checkpointPayload),
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      event_type: "rotation_started",
      rotation_kind: "dek",
      scope_kind: "document",
      scope_id: input.documentId,
      old_key_version: input.oldKeyVersion,
      new_key_version: input.newKeyVersion,
      not_before_event_sequence: sequence,
      reason: input.reason,
    },
  });
  return signedRotationAppend(input.workspaceId, checkpointPayload, [event]);
}

export function dekRotationCompletedEventHash(
  input: Omit<DekRotationCompletionKeyDirectoryAppendInput, "deletionManifestHash">,
): string {
  const checkpointPayload = checkpointPayloadWithHead(input.checkpointEnvelope);
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown>;
  return eventHash(
    dekRotationCompletedEvent({
      ...input,
      completedSequence: numberField(coveredHead.head_sequence) + 1,
      previousEventHash: stringField(coveredHead.head_hash),
    }),
  );
}

export async function buildDekRotationCompletionKeyDirectoryAppend(
  input: DekRotationCompletionKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = checkpointPayloadWithHead(input.checkpointEnvelope);
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown>;
  const completedSequence = numberField(coveredHead.head_sequence) + 1;
  const completionEvent = dekRotationCompletedEvent({
    ...input,
    completedSequence,
    previousEventHash: stringField(coveredHead.head_hash),
  });
  const deletionEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: completedSequence + 1,
    eventType: "old_key_deleted",
    actor: rotationActor(input, checkpointPayload),
    previousEventHash: eventHash(completionEvent),
    body: {
      event_type: "old_key_deleted",
      rotation_kind: "dek",
      scope_kind: "document",
      scope_id: input.documentId,
      old_key_version: input.oldKeyVersion,
      deleted_at_event_sequence: completedSequence + 1,
      deletion_manifest_hash: input.deletionManifestHash,
    },
  });
  return signedRotationAppend(input.workspaceId, checkpointPayload, [
    completionEvent,
    deletionEvent,
  ]);
}

export function buildDekOldKeyDeletionManifestHash(input: {
  documentId: string;
  oldKeyVersion: number;
  rotationCompletedEventHash: string;
  deletedSecretIdsHash: string;
  deletedWrapIdsHash: string;
  deviceKeyDeletionProofs: Record<string, unknown>[];
  wipeRequiredDeviceIds: string[];
  serverRejectsOldKeyUploadsAfterSequence: number;
}): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.old-key-deletion-manifest",
      version: CURRENT_PROTOCOL_VERSION,
      rotation_kind: "dek",
      scope_kind: "document",
      scope_id: input.documentId,
      old_key_version: input.oldKeyVersion,
      rotation_completed_event_hash: input.rotationCompletedEventHash,
      deleted_secret_ids_hash: input.deletedSecretIdsHash,
      deleted_wrap_ids_hash: input.deletedWrapIdsHash,
      active_device_deletion_proofs_hash: activeDeviceDeletionProofsHash(
        input.deviceKeyDeletionProofs,
      ),
      wipe_required_device_ids_hash: wipeRequiredDeviceIdsHash(input.wipeRequiredDeviceIds),
      server_rejects_old_key_uploads_after_sequence: input.serverRejectsOldKeyUploadsAfterSequence,
    }),
  );
}

function dekRotationCompletedEvent(
  input: Omit<DekRotationCompletionKeyDirectoryAppendInput, "deletionManifestHash"> & {
    completedSequence: number;
    previousEventHash: string;
  },
): Record<string, unknown> {
  const checkpointPayload = checkpointPayloadWithHead(input.checkpointEnvelope);
  return keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: input.completedSequence,
    eventType: "rotation_completed",
    actor: rotationActor(input, checkpointPayload),
    previousEventHash: input.previousEventHash,
    body: {
      event_type: "rotation_completed",
      rotation_kind: "dek",
      scope_kind: "document",
      scope_id: input.documentId,
      old_key_version: input.oldKeyVersion,
      new_key_version: input.newKeyVersion,
      completed_at_event_sequence: input.completedSequence,
      completion_manifest_hash: input.completionManifestHash,
    },
  });
}

function checkpointPayloadWithHead(envelope: KeyDirectoryEnvelope): Record<string, unknown> {
  const payload = envelope.payload as Record<string, unknown> | undefined;
  if (!payload) throw new Error("key_directory_checkpoint_payload_invalid");
  if (!payload.covered_event_head) throw new Error("key_directory_checkpoint_head_invalid");
  return payload;
}

function rotationActor(
  input: { workspaceId: string; actorUserId: string; actorDeviceId: string },
  checkpointPayload: Record<string, unknown>,
) {
  return actorWithCheckpointAuthority(
    deviceActor(
      input.actorUserId,
      input.actorDeviceId,
      activeDeviceSigningKeyId(checkpointPayload, input.actorDeviceId),
    ),
    "workspace",
    input.workspaceId,
    checkpointPayload,
  );
}

async function signedRotationAppend(
  workspaceId: string,
  checkpointPayload: Record<string, unknown>,
  events: Record<string, unknown>[],
): Promise<KeyDirectoryAppendArtifacts> {
  const signedEvents = await Promise.all(events.map((event) => signEvent("device", event)));
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(events.at(-1)!),
    identityKeys: (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
    deviceKeys: (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  return {
    events: signedEvents,
    checkpoint: await signCheckpoint("device", "workspace_authorized", checkpoint),
  };
}
