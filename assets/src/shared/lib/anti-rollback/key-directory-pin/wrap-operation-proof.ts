import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hydrateVerifiedKeyDirectoryLineage,
  lookupVerifiedKeyDirectoryCheckpointBodies,
  lookupVerifiedKeyDirectoryEventBodies,
  rememberVerifiedKeyDirectoryLineage,
} from "./pins";
import { assertEnvelope, checkpointHash, eventHash, numberField } from "./primitives";
import type { KeyDirectoryPin, SignedKeyDirectoryEnvelope } from "./types";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  signedPqWrapEventBody,
  signedPqWrapRecordFromEnvelope,
} from "@/shared/lib/crypto/signed-pq-wrap";

declare const verifiedSignedPqWrapOperation: unique symbol;

export interface VerifiedSignedPqWrapOperation {
  readonly protocol: "refmd.verified-signed-pq-wrap-operation";
  readonly version: 1;
  readonly sequence: number;
  readonly checkpointHash: string;
  readonly coveredHeadSequence: number;
  readonly coveredHeadHash: string;
  readonly wrapEventSequence: number;
  readonly wrapEventHash: string;
  readonly wrapEventBodyHash: string;
  readonly wrapBodyHash: string;
  readonly transcriptHash: string;
  readonly recordCommitmentHash: string;
  readonly [verifiedSignedPqWrapOperation]: true;
}

export async function verifyWorkspaceSignedPqWrapOperation(
  workspaceId: string,
  value: unknown,
): Promise<VerifiedSignedPqWrapOperation> {
  const container = record(value, "signed_pq_wrap_container_invalid");
  const wrap = signedPqWrapRecordFromEnvelope(container);
  if (wrap.event_scope.scope_kind !== "workspace" || wrap.event_scope.scope_id !== workspaceId) {
    throw new Error("signed_pq_wrap_workspace_scope_mismatch");
  }

  const checkpoint = assertEnvelope(
    record(
      container.workspace_key_directory_checkpoint,
      "signed_pq_wrap_operation_checkpoint_missing",
    ),
  );
  const operation = wrap.operation_checkpoint;
  const checkpointAncestry = arrayOfEnvelopes(
    container.workspace_key_directory_checkpoint_ancestry,
    "workspace_key_directory_checkpoint_ancestry_required",
  );
  const eventAncestry = arrayOfEnvelopes(
    container.workspace_key_directory_event_ancestry,
    "workspace_key_directory_event_ancestry_required",
  );
  const checkpointPayload = checkpoint.payload;
  const coveredHead = record(
    checkpointPayload.covered_event_head,
    "signed_pq_wrap_operation_checkpoint_head_invalid",
  );
  if (
    checkpointPayload.scope_kind !== "workspace" ||
    checkpointPayload.scope_id !== workspaceId ||
    numberField(checkpointPayload.sequence, "checkpoint_sequence_invalid") !==
      operation.checkpoint_sequence ||
    checkpointHash(checkpoint) !== operation.checkpoint_hash ||
    numberField(coveredHead.head_sequence, "event_head_sequence_invalid") !==
      operation.covered_event_head_sequence ||
    coveredHead.head_hash !== operation.covered_event_head_hash
  ) {
    throw new Error("signed_pq_wrap_operation_checkpoint_mismatch");
  }

  let current = await requireCurrentPin(workspaceId);
  if (operation.checkpoint_sequence > current.checkpointSequence) {
    await advanceToOperationCheckpoint(
      workspaceId,
      checkpoint,
      checkpointAncestry,
      eventAncestry,
      current,
    );
    current = await requireCurrentPin(workspaceId);
  }
  await hydrateVerifiedKeyDirectoryLineage("workspace", workspaceId, current);
  const checkpoints = uniqueEnvelopes(
    [
      ...lookupVerifiedKeyDirectoryCheckpointBodies("workspace", workspaceId),
      ...checkpointAncestry,
      checkpoint,
    ],
    checkpointHash,
  );
  const events = uniqueEnvelopes(
    [...lookupVerifiedKeyDirectoryEventBodies("workspace", workspaceId), ...eventAncestry],
    eventHash,
  );
  const checkpointProof = assertOperationCheckpointIsCurrentOrAncestor(
    workspaceId,
    checkpoint,
    current,
    checkpoints,
  );
  const eventProof = assertWrapEventIncluded(
    workspaceId,
    wrap,
    operation.covered_event_head_sequence,
    operation.covered_event_head_hash,
    events,
  );
  rememberVerifiedKeyDirectoryLineage({
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointEnvelope: checkpointProof.current,
    checkpointAncestry: checkpointProof.lineage.filter(
      (entry) => entry !== checkpointProof.current,
    ),
    eventAncestry: eventProof,
  });

  const eventBody = signedPqWrapEventBody(wrap) as Record<string, StrictJsonValue>;
  const wrapBodyHash = eventBody.wrap_body_hash;
  if (typeof wrapBodyHash !== "string" || wrapBodyHash.length === 0) {
    throw new Error("signed_pq_wrap_body_hash_invalid");
  }
  return {
    protocol: "refmd.verified-signed-pq-wrap-operation",
    version: 1,
    sequence: operation.checkpoint_sequence,
    checkpointHash: operation.checkpoint_hash,
    coveredHeadSequence: operation.covered_event_head_sequence,
    coveredHeadHash: operation.covered_event_head_hash,
    wrapEventSequence: wrap.event.wrap_event_sequence,
    wrapEventHash: wrap.event.wrap_event_hash,
    wrapEventBodyHash: wrap.event.wrap_event_body_hash,
    wrapBodyHash,
    transcriptHash: wrap.transcript_hash,
    recordCommitmentHash: blake3Base64Url(
      canonicalizeStrictBytes(wrap as unknown as StrictJsonValue),
    ),
  } as VerifiedSignedPqWrapOperation;
}

async function requireCurrentPin(workspaceId: string): Promise<KeyDirectoryPin> {
  const pin = await getKeyDirectoryPin("workspace", workspaceId);
  if (!pin) throw new Error("workspace_key_directory_pin_required");
  return pin;
}

async function advanceToOperationCheckpoint(
  workspaceId: string,
  checkpoint: SignedKeyDirectoryEnvelope,
  checkpointAncestry: SignedKeyDirectoryEnvelope[],
  eventAncestry: SignedKeyDirectoryEnvelope[],
  current: KeyDirectoryPin,
): Promise<void> {
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointEnvelope: checkpoint as unknown as Record<string, unknown>,
    checkpointAncestry: checkpointAncestry
      .filter(
        (entry) =>
          envelopeSequence(entry, "checkpoint_sequence_invalid") >= current.checkpointSequence &&
          envelopeSequence(entry, "checkpoint_sequence_invalid") <
            numberField(checkpoint.payload.sequence, "checkpoint_sequence_invalid"),
      )
      .map(envelopeRecord),
    eventAncestry: eventAncestry
      .filter(
        (entry) => envelopeSequence(entry, "event_sequence_invalid") > current.eventHeadSequence,
      )
      .map(envelopeRecord),
    authorityEventAncestry: eventAncestry.map(envelopeRecord),
  });
}

function assertOperationCheckpointIsCurrentOrAncestor(
  workspaceId: string,
  operationCheckpoint: SignedKeyDirectoryEnvelope,
  current: KeyDirectoryPin,
  checkpoints: SignedKeyDirectoryEnvelope[],
): {
  current: SignedKeyDirectoryEnvelope;
  lineage: SignedKeyDirectoryEnvelope[];
} {
  const operationSequence = numberField(
    operationCheckpoint.payload.sequence,
    "checkpoint_sequence_invalid",
  );
  const operationHash = checkpointHash(operationCheckpoint);
  if (operationSequence > current.checkpointSequence) {
    throw new Error("signed_pq_wrap_operation_checkpoint_ahead_of_pin");
  }
  if (operationSequence === current.checkpointSequence) {
    if (operationHash !== current.checkpointHash) {
      throw new Error("signed_pq_wrap_operation_checkpoint_fork");
    }
    return { current: operationCheckpoint, lineage: [operationCheckpoint] };
  }

  const descendants = assertBackwardLineage({
    kind: "checkpoint",
    bodies: checkpoints,
    scopeId: workspaceId,
    ancestorSequence: operationSequence,
    ancestorHash: operationHash,
    descendantSequence: current.checkpointSequence,
    descendantHash: current.checkpointHash,
  });
  const currentCheckpoint = checkpoints.find(
    (entry) =>
      numberField(entry.payload.sequence, "checkpoint_sequence_invalid") ===
        current.checkpointSequence && checkpointHash(entry) === current.checkpointHash,
  );
  if (!currentCheckpoint) throw new Error("signed_pq_wrap_checkpoint_lineage_missing");
  return {
    current: currentCheckpoint,
    lineage: [operationCheckpoint, ...descendants],
  };
}

function assertWrapEventIncluded(
  workspaceId: string,
  wrap: ReturnType<typeof signedPqWrapRecordFromEnvelope>,
  coveredHeadSequence: number,
  coveredHeadHash: string,
  events: SignedKeyDirectoryEnvelope[],
): SignedKeyDirectoryEnvelope[] {
  const wrapSequence = wrap.event.wrap_event_sequence;
  const wrapHash = wrap.event.wrap_event_hash;
  const event = events.find(
    (candidate) =>
      numberField(candidate.payload.sequence, "event_sequence_invalid") === wrapSequence &&
      eventHash(candidate) === wrapHash,
  );
  if (!event) throw new Error("signed_pq_wrap_event_missing");
  const expectedBody = signedPqWrapEventBody(wrap);
  if (
    event.payload.scope_kind !== "workspace" ||
    event.payload.scope_id !== workspaceId ||
    event.payload.event_type !== "wrap_issued" ||
    !sameStrictJson(event.payload.body, expectedBody) ||
    blake3Base64Url(canonicalizeStrictBytes(expectedBody)) !== wrap.event.wrap_event_body_hash
  ) {
    throw new Error("signed_pq_wrap_event_body_mismatch");
  }
  if (coveredHeadSequence < wrapSequence) {
    throw new Error("signed_pq_wrap_event_not_covered");
  }
  if (coveredHeadSequence === wrapSequence) {
    if (coveredHeadHash !== wrapHash) throw new Error("signed_pq_wrap_event_head_fork");
    return [event];
  }
  const descendants = assertBackwardLineage({
    kind: "event",
    bodies: events,
    scopeId: workspaceId,
    ancestorSequence: wrapSequence,
    ancestorHash: wrapHash,
    descendantSequence: coveredHeadSequence,
    descendantHash: coveredHeadHash,
  });
  return [event, ...descendants];
}

function assertBackwardLineage(params: {
  kind: "checkpoint" | "event";
  bodies: SignedKeyDirectoryEnvelope[];
  scopeId: string;
  ancestorSequence: number;
  ancestorHash: string;
  descendantSequence: number;
  descendantHash: string;
}): SignedKeyDirectoryEnvelope[] {
  let sequence = params.descendantSequence;
  let hash = params.descendantHash;
  const descendants: SignedKeyDirectoryEnvelope[] = [];
  while (sequence > params.ancestorSequence) {
    const candidate = params.bodies.find(
      (entry) =>
        numberField(
          entry.payload.sequence,
          params.kind === "checkpoint" ? "checkpoint_sequence_invalid" : "event_sequence_invalid",
        ) === sequence &&
        (params.kind === "checkpoint" ? checkpointHash(entry) : eventHash(entry)) === hash,
    );
    if (!candidate) throw new Error(`signed_pq_wrap_${params.kind}_lineage_missing`);
    descendants.push(candidate);
    if (
      candidate.payload.scope_kind !== "workspace" ||
      candidate.payload.scope_id !== params.scopeId
    ) {
      throw new Error(`signed_pq_wrap_${params.kind}_lineage_scope_mismatch`);
    }
    const previousHash =
      params.kind === "checkpoint"
        ? candidate.payload.previous_checkpoint_hash
        : candidate.payload.previous_event_hash;
    if (typeof previousHash !== "string" || previousHash.length === 0) {
      throw new Error(`signed_pq_wrap_${params.kind}_lineage_invalid`);
    }
    hash = previousHash;
    sequence -= 1;
  }
  if (sequence !== params.ancestorSequence || hash !== params.ancestorHash) {
    throw new Error(`signed_pq_wrap_${params.kind}_lineage_fork`);
  }
  return descendants;
}

function envelopeSequence(value: SignedKeyDirectoryEnvelope, code: string): number {
  return numberField(value.payload.sequence, code);
}

function arrayOfEnvelopes(value: unknown, code: string): SignedKeyDirectoryEnvelope[] {
  if (!Array.isArray(value) || value.some((entry) => !isRecord(entry))) throw new Error(code);
  return value.map((entry) => assertEnvelope(entry as Record<string, unknown>));
}

function envelopeRecord(value: SignedKeyDirectoryEnvelope): Record<string, unknown> {
  return value as unknown as Record<string, unknown>;
}

function uniqueEnvelopes(
  values: SignedKeyDirectoryEnvelope[],
  hash: (value: SignedKeyDirectoryEnvelope) => string,
): SignedKeyDirectoryEnvelope[] {
  return [
    ...new Map(
      values.map((entry) => [
        `${numberField(entry.payload.sequence, "key_directory_sequence_invalid")}:${hash(entry)}`,
        entry,
      ]),
    ).values(),
  ];
}

function sameStrictJson(left: unknown, right: unknown): boolean {
  const leftBytes = canonicalizeStrictBytes(left as StrictJsonValue);
  const rightBytes = canonicalizeStrictBytes(right as StrictJsonValue);
  return (
    leftBytes.length === rightBytes.length &&
    leftBytes.every((byte, index) => byte === rightBytes[index])
  );
}

function record(value: unknown, code: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(code);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
