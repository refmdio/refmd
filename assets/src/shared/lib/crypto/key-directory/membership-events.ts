import { blake3Base64Url } from "../hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import {
  activeDeviceSigningKeyId,
  activeIdentitySigningKeyId,
  actorWithCheckpointAuthority,
  checkpointHasKey,
  checkpointShareParticipantKeys,
  deviceActor,
  eventHash,
  eventHead,
  eventRef,
  eventRefForKey,
  identityActor,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  numberField,
  revokeKeyEntry,
  signCheckpoint,
  signEvent,
  stringField,
  uniqueStrings,
} from "./primitives";
import type {
  DeviceRevocationKeyDirectoryAppendInput,
  KeyDirectoryAppendArtifacts,
  WorkspaceMemberRemovalKeyDirectoryAppendInput,
  WorkspaceMemberRoleChangeKeyDirectoryAppendInput,
} from "./types";

export async function buildDeviceRevocationKeyDirectoryAppend(
  input: DeviceRevocationKeyDirectoryAppendInput,
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

  const signingRevokedEvent = keyDirectoryEvent({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "signing_key_revoked",
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      key_id: input.revokedSigningKeyId,
      reason: input.reason,
      revoked_at_event_sequence: numberField(coveredHead.head_sequence) + 1,
    },
  });
  const encryptionRevokedEvent = keyDirectoryEvent({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    sequence: numberField(coveredHead.head_sequence) + 2,
    eventType: "encryption_key_revoked",
    actor,
    previousEventHash: eventHash(signingRevokedEvent),
    body: {
      key_id: input.revokedEncryptionKeyId,
      reason: input.reason,
      revoked_at_event_sequence: numberField(coveredHead.head_sequence) + 2,
    },
  });
  const signedSigningEvent = await signEvent(
    input.scopeKind === "user" ? "identity" : "device",
    signingRevokedEvent,
  );
  const signedEncryptionEvent = await signEvent(
    input.scopeKind === "user" ? "identity" : "device",
    encryptionRevokedEvent,
  );
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(encryptionRevokedEvent),
    identityKeys: revokeKeyEntry(
      (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
      input.revokedSigningKeyId,
      eventRef(input.scopeKind, input.scopeId, signingRevokedEvent),
    ),
    deviceKeys: revokeKeyEntry(
      revokeKeyEntry(
        (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
        input.revokedSigningKeyId,
        eventRef(input.scopeKind, input.scopeId, signingRevokedEvent),
      ),
      input.revokedEncryptionKeyId,
      eventRef(input.scopeKind, input.scopeId, encryptionRevokedEvent),
    ),
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: uniqueStrings([
      ...((checkpointPayload.revoked_key_ids as string[] | undefined) ?? []),
      input.revokedSigningKeyId,
      input.revokedEncryptionKeyId,
    ]),
  });
  const signedCheckpoint = await signCheckpoint(
    input.scopeKind === "user" ? "identity" : "device",
    input.scopeKind === "user" ? "identity_active" : "workspace_authorized",
    checkpoint,
  );
  return { events: [signedSigningEvent, signedEncryptionEvent], checkpoint: signedCheckpoint };
}

export async function buildWorkspaceMemberRemovalKeyDirectoryAppend(
  input: WorkspaceMemberRemovalKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
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
  const startingSequence = numberField(coveredHead.head_sequence) + 1;
  const memberRemovedEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: startingSequence,
    eventType: "member_removed",
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      workspace_id: input.workspaceId,
      user_id: input.removedUserId,
      removed_at_event_sequence: startingSequence,
    },
  });

  const revocableDeviceKeys = input.removedDeviceKeys.filter(
    (keys) =>
      checkpointHasKey(checkpointPayload, keys.signingKeyId) &&
      checkpointHasKey(checkpointPayload, keys.encryptionKeyId),
  );

  const events = revocableDeviceKeys.reduce<Record<string, unknown>[]>(
    (acc, deviceKeys) => {
      const previous = acc[acc.length - 1] ?? memberRemovedEvent;
      const encryptionSequence = startingSequence + acc.length;
      const encryptionEvent = keyDirectoryEvent({
        scopeKind: "workspace",
        scopeId: input.workspaceId,
        sequence: encryptionSequence,
        eventType: "encryption_key_revoked",
        actor,
        previousEventHash: eventHash(previous),
        body: {
          key_id: deviceKeys.encryptionKeyId,
          reason: "member_removed",
          revoked_at_event_sequence: encryptionSequence,
        },
      });
      const signingSequence = encryptionSequence + 1;
      const signingEvent = keyDirectoryEvent({
        scopeKind: "workspace",
        scopeId: input.workspaceId,
        sequence: signingSequence,
        eventType: "signing_key_revoked",
        actor,
        previousEventHash: eventHash(encryptionEvent),
        body: {
          key_id: deviceKeys.signingKeyId,
          reason: "member_removed",
          revoked_at_event_sequence: signingSequence,
        },
      });
      return [...acc, encryptionEvent, signingEvent];
    },
    [memberRemovedEvent],
  );
  const signedEvents = await Promise.all(events.map((event) => signEvent("device", event)));
  const revokedDeviceKeys = revocableDeviceKeys.reduce(
    (entries, deviceKeys) =>
      revokeKeyEntry(
        revokeKeyEntry(
          entries,
          deviceKeys.signingKeyId,
          eventRefForKey(events, deviceKeys.signingKeyId),
        ),
        deviceKeys.encryptionKeyId,
        eventRefForKey(events, deviceKeys.encryptionKeyId),
      ),
    (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
  );
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(events[events.length - 1] ?? memberRemovedEvent),
    identityKeys: (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
    deviceKeys: revokedDeviceKeys,
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: uniqueStrings([
      ...((checkpointPayload.revoked_key_ids as string[] | undefined) ?? []),
      ...revocableDeviceKeys.flatMap((keys) => [keys.signingKeyId, keys.encryptionKeyId]),
    ]),
  });
  const signedCheckpoint = await signCheckpoint("device", "workspace_authorized", checkpoint);
  return { events: signedEvents, checkpoint: signedCheckpoint };
}

export async function buildWorkspaceMemberRoleChangesKeyDirectoryAppend(
  input: WorkspaceMemberRoleChangeKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
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
  if (input.changes.length === 0) throw new Error("member_role_changes_empty");
  let previousEventHash = stringField(coveredHead.head_hash);
  let sequence = numberField(coveredHead.head_sequence);
  const signedEvents = [];
  let lastEvent: Record<string, unknown> | null = null;
  for (const change of input.changes) {
    sequence += 1;
    const event = keyDirectoryEvent({
      scopeKind: "workspace",
      scopeId: input.workspaceId,
      sequence,
      eventType: "member_role_changed",
      actor,
      previousEventHash,
      body: {
        workspace_id: input.workspaceId,
        user_id: change.targetUserId,
        previous_role_id: change.previousRoleId,
        previous_base_role: change.previousBaseRole,
        previous_effective_permissions: canonicalPermissions(change.previousEffectivePermissions),
        role_id: change.roleId,
        base_role: change.baseRole,
        effective_permissions: canonicalPermissions(change.effectivePermissions),
        permission_version: change.permissionVersion,
        changed_at_event_sequence: sequence,
      },
    });
    signedEvents.push(await signEvent("device", event));
    previousEventHash = eventHash(event);
    lastEvent = event;
  }
  if (!lastEvent) throw new Error("member_role_changes_empty");
  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(lastEvent),
    identityKeys: (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
    deviceKeys: (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint("device", "workspace_authorized", checkpoint);
  return { events: signedEvents, checkpoint: signedCheckpoint };
}

function canonicalPermissions(permissions: string[]): string[] {
  return [...new Set(permissions)].sort();
}
