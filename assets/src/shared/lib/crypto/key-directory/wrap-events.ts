import { blake3Base64Url } from "../hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import { signedPqWrapEventBody } from "../signed-pq-wrap";
import {
  eventHash,
  eventHead,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  numberField,
  signCheckpoint,
  signEvent,
  stringField,
} from "./primitives";
import type { KeyDirectoryAppendArtifacts, WrapIssuedKeyDirectoryAppendInput } from "./types";

export async function buildWrapIssuedKeyDirectoryAppend(
  input: WrapIssuedKeyDirectoryAppendInput,
): Promise<KeyDirectoryAppendArtifacts> {
  const checkpointPayload = input.checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  const event = wrapIssuedKeyDirectoryEventFromRecord({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    coveredHead,
    wrapRecord: input.wrapRecord,
  });

  const signedEvent = await signEvent("device", event);
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
    deviceKeys: (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
    shareParticipantKeys:
      (checkpointPayload.share_participant_keys as Record<string, unknown>[] | undefined) ?? [],
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const signedCheckpoint = await signCheckpoint(
    input.scopeKind === "user" ? "identity" : "device",
    input.scopeKind === "user" ? "identity_active" : "workspace_authorized",
    checkpoint,
  );
  return { events: [signedEvent], checkpoint: signedCheckpoint };
}

export function wrapIssuedKeyDirectoryEventFromRecord(input: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  coveredHead: Record<string, unknown>;
  wrapRecord: WrapIssuedKeyDirectoryAppendInput["wrapRecord"];
}): Record<string, unknown> {
  const sender = input.wrapRecord.sender as Record<string, unknown>;
  const actor = {
    signer_kind: stringField(sender.signer_kind),
    user_id: stringField(sender.user_id),
    device_id: stringField(sender.device_id),
    signing_key_id: stringField(sender.signing_key_id),
    key_scope_kind: stringField(sender.key_scope_kind),
    key_scope_id: stringField(sender.key_scope_id),
    key_checkpoint_sequence: numberField(sender.key_checkpoint_sequence),
    key_checkpoint_hash: stringField(sender.key_checkpoint_hash),
  };
  const event = keyDirectoryEvent({
    scopeKind: input.scopeKind,
    scopeId: input.scopeId,
    sequence: numberField(input.coveredHead.head_sequence) + 1,
    eventType: "wrap_issued",
    actor,
    previousEventHash: stringField(input.coveredHead.head_hash),
    body: signedPqWrapEventBody(input.wrapRecord) as Record<string, unknown>,
  });

  const wrapEvent = input.wrapRecord.event as Record<string, unknown> | undefined;
  if (!wrapEvent || eventHash(event) !== wrapEvent.wrap_event_hash) {
    throw new Error("wrap_issued_event_hash_mismatch");
  }

  return event;
}
