import { getCryptoWorker } from "../worker/client";
import { blake3Base64Url } from "../hash";
import { computeHybridEncryptionKeyId } from "../hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import { computeSigningKeyId } from "../signature";
import {
  activeIdentitySigningKeyId,
  activeIdentityEncryptionKeyId,
  actorWithCheckpointAuthority,
  eventHead,
  eventRef,
  identityActor,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  keyEntry,
  numberField,
  revokeKeyEntry,
  signatureEnvelope,
  stringField,
} from "./primitives";
import {
  assertKeyDirectoryEnvelope,
  type IdentityRotationKeyDirectoryAppendInput,
  type KeyDirectoryAppendArtifacts,
} from "./types";

export async function buildIdentityRotationKeyDirectoryAppend(
  input: IdentityRotationKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const previous = input.checkpointEnvelope.payload as Record<string, unknown>;
  const coveredHead = previous.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");

  const oldSigningKeyId = activeIdentitySigningKeyId(previous, input.userId);
  const oldEncryptionKeyId = activeIdentityEncryptionKeyId(previous, input.userId);
  const successorEncryptionKeyId = computeHybridEncryptionKeyId(
    input.successorHybridEncryptionPublicKeyMaterial,
  );
  const successorSigningKeyId = computeSigningKeyId(input.successorHybridSigningPublicKeyMaterial);
  const actor = actorWithCheckpointAuthority(
    identityActor(input.userId, oldSigningKeyId),
    "user",
    input.userId,
    previous,
  );
  const startedEvent = keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "rotation_started",
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      event_type: "rotation_started",
      rotation_kind: "identity",
      scope_kind: "user",
      scope_id: input.userId,
      old_identity_signing_key_id: oldSigningKeyId,
      old_identity_encryption_key_id: oldEncryptionKeyId,
      new_identity_signing_key_id: successorSigningKeyId,
      new_identity_encryption_key_id: successorEncryptionKeyId,
      old_user_checkpoint_sequence: numberField(previous.sequence),
      old_user_checkpoint_hash: blake3Base64Url(
        canonicalizeStrictBytes(previous as StrictJsonValue),
      ),
      new_key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes({
          hybrid_encryption_public_key_material:
            input.successorHybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
          hybrid_signing_public_key_material:
            input.successorHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
        }),
      ),
      not_before_event_sequence: numberField(coveredHead.head_sequence) + 1,
      reason: "scheduled",
    },
  });
  const event = keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: numberField(coveredHead.head_sequence) + 2,
    eventType: "identity_key_added",
    actor,
    previousEventHash: eventHead(startedEvent).head_hash as string,
    body: {
      key_id: successorSigningKeyId,
      key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          input.successorHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
        ),
      ),
    },
  });
  const worker = getCryptoWorker();
  const signedStartedArtifact = await worker.signIdentityKeyDirectoryEvent({
    eventType: "rotation_started",
    eventPayload: startedEvent,
    rotationPreviousCheckpointPayload: previous,
  });
  const signedEventArtifact = await worker.signIdentityKeyDirectoryEvent({
    eventType: "identity_key_added",
    eventPayload: event,
    rotationPreviousCheckpointPayload: previous,
    rotationStartedEventPayload: startedEvent,
  });
  const signedEvent = assertKeyDirectoryEnvelope(
    { payload: event, signatures: [signatureEnvelope(signedEventArtifact)] },
    "key_directory_signed_event_invalid",
  );
  const validFrom = eventRef("user", input.userId, event);
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: numberField(previous.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(canonicalizeStrictBytes(previous as StrictJsonValue)),
    coveredEventHead: eventHead(event),
    identityKeys: [
      ...((previous.identity_keys as Record<string, unknown>[] | undefined) ?? []),
      keyEntry(
        successorEncryptionKeyId,
        input.successorHybridEncryptionPublicKeyMaterial,
        validFrom,
      ),
      keyEntry(successorSigningKeyId, input.successorHybridSigningPublicKeyMaterial, validFrom),
    ],
    deviceKeys: (previous.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys:
      (previous.share_participant_keys as Record<string, unknown>[] | undefined) ?? [],
    revokedKeyIds: (previous.revoked_key_ids as string[] | undefined) ?? [],
  });
  const params = {
    variant: "identity_rotation" as const,
    checkpointPayload: checkpoint,
    rotationPreviousCheckpointPayload: previous,
    rotationEventPayload: event,
    rotationStartedEventPayload: startedEvent,
  };
  const [oldSignature, successorSignature] = await Promise.all([
    worker.signIdentityKeyDirectoryCheckpoint(params),
    worker.signIdentitySuccessorKeyDirectoryCheckpoint(params),
  ]);

  return {
    events: [
      assertKeyDirectoryEnvelope(
        { payload: startedEvent, signatures: [signatureEnvelope(signedStartedArtifact)] },
        "key_directory_signed_event_invalid",
      ),
      signedEvent,
    ],
    checkpoint: assertKeyDirectoryEnvelope(
      {
        payload: checkpoint,
        signatures: [signatureEnvelope(oldSignature), signatureEnvelope(successorSignature)],
      },
      "key_directory_signed_checkpoint_invalid",
    ),
  };
}

export async function buildIdentityRetirementKeyDirectoryAppend(input: {
  userId: string;
  checkpointEnvelope: IdentityRotationKeyDirectoryAppendInput["checkpointEnvelope"];
  successorSigningKeyId: string;
  oldSigningKeyId: string;
  oldEncryptionKeyId: string;
  oldKeyVersion: number;
  newKeyVersion: number;
  completionManifestHash: string;
  deletionManifestHash: string;
}): Promise<KeyDirectoryAppendArtifacts> {
  const previous = input.checkpointEnvelope.payload as Record<string, unknown>;
  const coveredHead = previous.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  const actor = actorWithCheckpointAuthority(
    identityActor(input.userId, input.successorSigningKeyId),
    "user",
    input.userId,
    previous,
  );
  const signingEvent = keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "signing_key_revoked",
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      key_id: input.oldSigningKeyId,
      reason: "rotation",
      revoked_at_event_sequence: numberField(coveredHead.head_sequence) + 1,
    },
  });
  const encryptionEvent = keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: numberField(coveredHead.head_sequence) + 2,
    eventType: "encryption_key_revoked",
    actor,
    previousEventHash: eventHead(signingEvent).head_hash as string,
    body: {
      key_id: input.oldEncryptionKeyId,
      reason: "rotation",
      revoked_at_event_sequence: numberField(coveredHead.head_sequence) + 2,
    },
  });
  const completedEvent = keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: numberField(coveredHead.head_sequence) + 3,
    eventType: "rotation_completed",
    actor,
    previousEventHash: eventHead(encryptionEvent).head_hash as string,
    body: {
      event_type: "rotation_completed",
      rotation_kind: "identity",
      scope_kind: "user",
      scope_id: input.userId,
      old_identity_signing_key_id: input.oldSigningKeyId,
      new_identity_signing_key_id: input.successorSigningKeyId,
      old_user_checkpoint_hash: stringField(previous.previous_checkpoint_hash),
      new_user_checkpoint_hash: blake3Base64Url(
        canonicalizeStrictBytes(previous as StrictJsonValue),
      ),
      completed_at_event_sequence: numberField(coveredHead.head_sequence) + 3,
      completion_manifest_hash: input.completionManifestHash,
    },
  });
  const deletedEvent = keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: numberField(coveredHead.head_sequence) + 4,
    eventType: "old_key_deleted",
    actor,
    previousEventHash: eventHead(completedEvent).head_hash as string,
    body: {
      event_type: "old_key_deleted",
      rotation_kind: "identity",
      scope_kind: "user",
      scope_id: input.userId,
      old_identity_signing_key_id: input.oldSigningKeyId,
      old_identity_encryption_key_id: input.oldEncryptionKeyId,
      new_identity_signing_key_id: input.successorSigningKeyId,
      rotation_completed_event_hash: eventHead(completedEvent).head_hash as string,
      deleted_at_event_sequence: numberField(coveredHead.head_sequence) + 4,
      deletion_manifest_hash: input.deletionManifestHash,
    },
  });
  const worker = getCryptoWorker();
  const signSuccessorEvent = async (event: Record<string, unknown>) => {
    const signed = await worker.signIdentitySuccessorKeyDirectoryEvent({
      eventType: event.event_type as string,
      eventPayload: event,
    });
    return assertKeyDirectoryEnvelope(
      { payload: event, signatures: [signatureEnvelope(signed)] },
      "key_directory_signed_event_invalid",
    );
  };
  const events = await Promise.all([
    signSuccessorEvent(signingEvent),
    signSuccessorEvent(encryptionEvent),
    signSuccessorEvent(completedEvent),
    signSuccessorEvent(deletedEvent),
  ]);
  const identityKeys = revokeKeyEntry(
    revokeKeyEntry(
      (previous.identity_keys as Record<string, unknown>[] | undefined) ?? [],
      input.oldSigningKeyId,
      eventRef("user", input.userId, signingEvent),
    ),
    input.oldEncryptionKeyId,
    eventRef("user", input.userId, encryptionEvent),
  );
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: numberField(previous.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(canonicalizeStrictBytes(previous as StrictJsonValue)),
    coveredEventHead: eventHead(deletedEvent),
    identityKeys,
    deviceKeys: (previous.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys:
      (previous.share_participant_keys as Record<string, unknown>[] | undefined) ?? [],
    revokedKeyIds: Array.from(
      new Set([
        ...((previous.revoked_key_ids as string[] | undefined) ?? []),
        input.oldSigningKeyId,
        input.oldEncryptionKeyId,
      ]),
    ),
  });
  const signedCheckpoint = await worker.signIdentitySuccessorKeyDirectoryCheckpoint({
    variant: "identity_active",
    checkpointPayload: checkpoint,
  });
  return {
    events,
    checkpoint: assertKeyDirectoryEnvelope(
      { payload: checkpoint, signatures: [signatureEnvelope(signedCheckpoint)] },
      "key_directory_signed_checkpoint_invalid",
    ),
  };
}

export function identityRotationCompletedEventHash(input: {
  userId: string;
  checkpointEnvelope: IdentityRotationKeyDirectoryAppendInput["checkpointEnvelope"];
  successorSigningKeyId: string;
  oldKeyVersion: number;
  newKeyVersion: number;
  completionManifestHash: string;
}): string {
  const previous = input.checkpointEnvelope.payload as Record<string, unknown>;
  const coveredHead = previous.covered_event_head as Record<string, unknown>;
  const actor = actorWithCheckpointAuthority(
    identityActor(input.userId, input.successorSigningKeyId),
    "user",
    input.userId,
    previous,
  );
  const signingEvent = identityRevocationEvent(input, "signing_key_revoked", {
    keyId: activeIdentitySigningKeyId(previous, input.userId),
    sequence: numberField(coveredHead.head_sequence) + 1,
    previousEventHash: stringField(coveredHead.head_hash),
  });
  const encryptionEvent = identityRevocationEvent(input, "encryption_key_revoked", {
    keyId: activeIdentityEncryptionKeyId(previous, input.userId),
    sequence: numberField(coveredHead.head_sequence) + 2,
    previousEventHash: eventHead(signingEvent).head_hash as string,
  });
  return blake3Base64Url(
    canonicalizeStrictBytes(
      keyDirectoryEvent({
        scopeKind: "user",
        scopeId: input.userId,
        sequence: numberField(coveredHead.head_sequence) + 3,
        eventType: "rotation_completed",
        actor,
        previousEventHash: eventHead(encryptionEvent).head_hash as string,
        body: {
          event_type: "rotation_completed",
          rotation_kind: "identity",
          scope_kind: "user",
          scope_id: input.userId,
          old_identity_signing_key_id: activeIdentitySigningKeyId(previous, input.userId),
          new_identity_signing_key_id: input.successorSigningKeyId,
          old_user_checkpoint_hash: stringField(previous.previous_checkpoint_hash),
          new_user_checkpoint_hash: blake3Base64Url(
            canonicalizeStrictBytes(previous as StrictJsonValue),
          ),
          completed_at_event_sequence: numberField(coveredHead.head_sequence) + 3,
          completion_manifest_hash: input.completionManifestHash,
        },
      }) as StrictJsonValue,
    ),
  );
}

export function identityRevokedOldIdentityPublicKeyEventHash(input: {
  userId: string;
  checkpointEnvelope: IdentityRotationKeyDirectoryAppendInput["checkpointEnvelope"];
  successorSigningKeyId: string;
}): string {
  const previous = input.checkpointEnvelope.payload as Record<string, unknown>;
  const coveredHead = previous.covered_event_head as Record<string, unknown>;
  return eventHead(
    identityRevocationEvent(input, "signing_key_revoked", {
      keyId: activeIdentitySigningKeyId(previous, input.userId),
      sequence: numberField(coveredHead.head_sequence) + 1,
      previousEventHash: stringField(coveredHead.head_hash),
    }),
  ).head_hash as string;
}

function identityRevocationEvent(
  input: {
    userId: string;
    checkpointEnvelope: IdentityRotationKeyDirectoryAppendInput["checkpointEnvelope"];
    successorSigningKeyId: string;
  },
  eventType: "signing_key_revoked" | "encryption_key_revoked",
  event: { keyId: string; sequence: number; previousEventHash: string },
): Record<string, unknown> {
  const previous = input.checkpointEnvelope.payload as Record<string, unknown>;
  return keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: event.sequence,
    eventType,
    actor: actorWithCheckpointAuthority(
      identityActor(input.userId, input.successorSigningKeyId),
      "user",
      input.userId,
      previous,
    ),
    previousEventHash: event.previousEventHash,
    body: {
      key_id: event.keyId,
      reason: "rotation",
      revoked_at_event_sequence: event.sequence,
    },
  });
}

export function identityDeletionManifestHash(input: {
  userId: string;
  oldIdentitySigningKeyId: string;
  oldIdentityEncryptionKeyId: string;
  newIdentitySigningKeyId: string;
  deletedIdentitySecretIdsHash: string;
  rotationCompletedEventHash: string;
  deviceKeyDeletionProofs: Record<string, unknown>[];
  wipeRequiredDeviceIds: string[];
  serverRejectsOldIdentityAfterSequence: number;
}): string {
  return blake3Base64Url(canonicalizeStrictBytes(identityDeletionManifest(input)));
}

export function identityDeletionManifest(input: {
  userId: string;
  oldIdentitySigningKeyId: string;
  oldIdentityEncryptionKeyId: string;
  newIdentitySigningKeyId: string;
  deletedIdentitySecretIdsHash: string;
  rotationCompletedEventHash: string;
  deviceKeyDeletionProofs: Record<string, unknown>[];
  wipeRequiredDeviceIds: string[];
  serverRejectsOldIdentityAfterSequence: number;
}): IdentityDeletionManifest {
  const proofHashes = input.deviceKeyDeletionProofs
    .map((proof) => blake3Base64Url(canonicalizeStrictBytes(proof.payload as StrictJsonValue)))
    .sort();
  return {
    protocol: "refmd.identity-old-key-deletion-manifest",
    version: 1,
    rotation_kind: "identity",
    scope_kind: "user",
    scope_id: input.userId,
    old_identity_signing_key_id: input.oldIdentitySigningKeyId,
    old_identity_encryption_key_id: input.oldIdentityEncryptionKeyId,
    new_identity_signing_key_id: input.newIdentitySigningKeyId,
    rotation_completed_event_hash: input.rotationCompletedEventHash,
    deleted_identity_secret_ids_hash: input.deletedIdentitySecretIdsHash,
    active_identity_deletion_proofs_hash: blake3Base64Url(
      canonicalizeStrictBytes({ proof_hashes: proofHashes }),
    ),
    wipe_required_device_ids_hash: blake3Base64Url(
      canonicalizeStrictBytes({ device_ids: [...input.wipeRequiredDeviceIds].sort() }),
    ),
    server_rejects_old_identity_after_sequence: input.serverRejectsOldIdentityAfterSequence,
  };
}

interface IdentityDeletionManifest extends Record<string, StrictJsonValue> {
  protocol: "refmd.identity-old-key-deletion-manifest";
  version: 1;
  rotation_kind: "identity";
  scope_kind: "user";
  scope_id: string;
  old_identity_signing_key_id: string;
  old_identity_encryption_key_id: string;
  new_identity_signing_key_id: string;
  rotation_completed_event_hash: string;
  deleted_identity_secret_ids_hash: string;
  active_identity_deletion_proofs_hash: string;
  wipe_required_device_ids_hash: string;
  server_rejects_old_identity_after_sequence: number;
}
