import { blake3Base64Url } from "../hash";
import { computeHybridEncryptionKeyId } from "../hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import { computeSigningKeyId } from "../signature";

import {
  activeDeviceSigningKeyId,
  activeIdentitySigningKeyId,
  actorWithCheckpointAuthority,
  checkpointShareParticipantKeys,
  deviceActor,
  eventHead,
  eventRef,
  identityActor,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  keyEntry,
  keyEntries,
  numberField,
  signCheckpoint,
  signEvent,
  stringField,
} from "./primitives";
import type {
  DeviceKeyDirectoryAppendInput,
  IdentityKeyDirectoryAppendInput,
  KeyDirectoryAppendArtifacts,
  RecoveryWorkspaceDeviceKeyDirectoryAppendInput,
} from "./types";

export async function buildDeviceKeyDirectoryAppend(
  input: DeviceKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  const actor = actorWithCheckpointAuthority(
    input.scopeKind === "user"
      ? identityActor(input.userId, activeIdentitySigningKeyId(checkpointPayload, input.userId))
      : deviceActor(
          input.userId,
          input.actorDeviceId ?? "",
          activeDeviceSigningKeyId(checkpointPayload, input.actorDeviceId ?? ""),
        ),
    input.scopeKind,
    input.scopeId,
    checkpointPayload,
  );

  const event = keyDirectoryEvent({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "device_key_added",
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      user_id: input.recipientUserId ?? input.userId,
      device_id: input.recipientDeviceId,
      signing_key_id: computeSigningKeyId(input.recipientHybridSigningPublicKeyMaterial),
      encryption_key_id: computeHybridEncryptionKeyId(
        input.recipientHybridEncryptionPublicKeyMaterial,
      ),
    },
  });
  const eventRefValue = eventRef(input.scopeKind, input.scopeId, event);
  const signedEvent = await signEvent(input.scopeKind === "user" ? "identity" : "device", event);
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(event),
    identityKeys: (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
    deviceKeys: [
      ...((checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? []),
      keyEntry(
        computeSigningKeyId(input.recipientHybridSigningPublicKeyMaterial),
        input.recipientHybridSigningPublicKeyMaterial,
        eventRefValue,
      ),
      keyEntry(
        computeHybridEncryptionKeyId(input.recipientHybridEncryptionPublicKeyMaterial),
        input.recipientHybridEncryptionPublicKeyMaterial,
        eventRefValue,
      ),
    ],
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint(
    input.scopeKind === "user" ? "identity" : "device",
    input.scopeKind === "user" ? "identity_active" : "workspace_authorized",
    checkpoint,
  );
  return { events: [signedEvent], checkpoint: signedCheckpoint };
}

export async function buildRecoveryWorkspaceDeviceKeyDirectoryAppend(
  input: RecoveryWorkspaceDeviceKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  const actor = actorWithCheckpointAuthority(
    identityActor(input.userId, activeIdentitySigningKeyId(checkpointPayload, input.userId)),
    "workspace",
    input.workspaceId,
    checkpointPayload,
  );
  const event = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "device_key_added",
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      user_id: input.userId,
      device_id: input.recipientDeviceId,
      signing_key_id: computeSigningKeyId(input.recipientHybridSigningPublicKeyMaterial),
      encryption_key_id: computeHybridEncryptionKeyId(
        input.recipientHybridEncryptionPublicKeyMaterial,
      ),
    },
  });
  const eventRefValue = eventRef("workspace", input.workspaceId, event);
  const signedEvent = await signEvent("identity", event);
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(event),
    identityKeys: keyEntries(checkpointPayload, "identity_keys"),
    deviceKeys: [
      ...keyEntries(checkpointPayload, "device_keys"),
      keyEntry(
        computeSigningKeyId(input.recipientHybridSigningPublicKeyMaterial),
        input.recipientHybridSigningPublicKeyMaterial,
        eventRefValue,
      ),
      keyEntry(
        computeHybridEncryptionKeyId(input.recipientHybridEncryptionPublicKeyMaterial),
        input.recipientHybridEncryptionPublicKeyMaterial,
        eventRefValue,
      ),
    ],
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint("device", "device_authorized", checkpoint);
  return { events: [signedEvent], checkpoint: signedCheckpoint };
}

export async function buildIdentityKeyDirectoryAppend(
  input: IdentityKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  const existingIdentityKeys =
    (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [];
  const encryptionKeyId = computeHybridEncryptionKeyId(
    input.recipientHybridEncryptionPublicKeyMaterial,
  );
  const signingKeyId = input.recipientHybridSigningPublicKeyMaterial
    ? computeSigningKeyId(input.recipientHybridSigningPublicKeyMaterial)
    : null;
  const eventKeyId =
    !checkpointHasKey(existingIdentityKeys, encryptionKeyId) || !signingKeyId
      ? encryptionKeyId
      : signingKeyId;
  const eventKeyMaterial =
    eventKeyId === encryptionKeyId
      ? input.recipientHybridEncryptionPublicKeyMaterial
      : input.recipientHybridSigningPublicKeyMaterial;
  if (!eventKeyMaterial) throw new Error("key_directory_identity_key_material_missing");
  const actor = actorWithCheckpointAuthority(
    deviceActor(
      input.userId,
      input.actorDeviceId,
      activeDeviceSigningKeyId(checkpointPayload, input.actorDeviceId),
    ),
    input.scopeKind,
    input.scopeId,
    checkpointPayload,
  );

  const event = keyDirectoryEvent({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "identity_key_added",
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      key_id: eventKeyId,
      key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(eventKeyMaterial as unknown as StrictJsonValue),
      ),
    },
  });
  const eventRefValue = eventRef(input.scopeKind, input.scopeId, event);
  const signedEvent = await signEvent("device", event);
  const identityKeys = appendKeyEntriesIfMissing(existingIdentityKeys, [
    keyEntry(encryptionKeyId, input.recipientHybridEncryptionPublicKeyMaterial, eventRefValue),
    ...(input.recipientHybridSigningPublicKeyMaterial && signingKeyId
      ? [keyEntry(signingKeyId, input.recipientHybridSigningPublicKeyMaterial, eventRefValue)]
      : []),
  ]);
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(event),
    identityKeys,
    deviceKeys: (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint("device", "workspace_authorized", checkpoint);
  return { events: [signedEvent], checkpoint: signedCheckpoint };
}

function checkpointHasKey(entries: Record<string, unknown>[], keyId: string): boolean {
  return entries.some((entry) => entry.key_id === keyId && !("revoked_at" in entry));
}

function appendKeyEntriesIfMissing(
  entries: Record<string, unknown>[],
  candidates: Record<string, unknown>[],
): Record<string, unknown>[] {
  return candidates.reduce((acc, candidate) => {
    const keyId = stringField(candidate.key_id);
    return checkpointHasKey(acc, keyId) ? acc : [...acc, candidate];
  }, entries);
}
