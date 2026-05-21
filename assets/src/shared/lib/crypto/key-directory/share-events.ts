import { blake3Base64Url } from "../hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import {
  activeDeviceSigningKeyId,
  actorWithCheckpointAuthority,
  checkpointShareParticipantKeys,
  deviceActor,
  eventHead,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  keyEntries,
  numberField,
  signCheckpoint,
  signEvent,
  stringField,
} from "./primitives";
import type {
  KeyDirectoryAppendArtifacts,
  KeyDirectoryEnvelope,
  ShareCreatedKeyDirectoryAppendInput,
  ShareManagementKeyDirectoryAppendInput,
} from "./types";

export async function buildShareCreatedKeyDirectoryAppend(
  input: ShareCreatedKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  return buildWorkspaceShareEventAppend({ ...input, eventType: "share_created" });
}

export async function buildShareManagementKeyDirectoryAppend(
  input: ShareManagementKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  return buildWorkspaceShareEventAppend(input);
}

async function buildWorkspaceShareEventAppend(input: {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  eventType:
    | "share_created"
    | "share_metadata_updated"
    | "share_revoked"
    | "share_exclusion_changed"
    | "share_key_scope_added"
    | "share_key_scope_replaced"
    | "share_key_scope_removed";
  body: Record<string, unknown>;
}): Promise<KeyDirectoryAppendArtifacts> {
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
  const event = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: input.eventType,
    actor,
    previousEventHash: stringField(coveredHead.head_hash),
    body: input.body,
  });
  const signedEvent = await signEvent("device", event);
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
    deviceKeys: keyEntries(checkpointPayload, "device_keys"),
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint("device", "workspace_authorized", checkpoint);
  return { events: [signedEvent], checkpoint: signedCheckpoint };
}

export async function buildWorkspaceBatchCheckpoint(input: {
  workspaceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  events: KeyDirectoryEnvelope[];
}): Promise<KeyDirectoryEnvelope> {
  if (input.events.length === 0) throw new Error("key_directory_batch_events_required");
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const lastEventPayload = input.events[input.events.length - 1]?.payload as
    | Record<string, unknown>
    | undefined;
  if (!lastEventPayload) throw new Error("key_directory_batch_event_payload_invalid");

  const checkpoint = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: blake3Base64Url(
      canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
    ),
    coveredEventHead: eventHead(lastEventPayload),
    identityKeys: (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
    deviceKeys: (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys:
      (checkpointPayload.share_participant_keys as Record<string, unknown>[] | undefined) ?? [],
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });

  return signCheckpoint("device", "workspace_authorized", checkpoint);
}
