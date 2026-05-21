import {
  assertShareParticipantCheckpointAdvance,
  pinFromCheckpoint,
  verifyCheckpointAncestry,
  verifyCheckpointSignatures,
  verifyEventAncestry,
  verifyInitialReplay,
} from "./verification";
import { assertEnvelope, checkpointHash, eventHash, numberField } from "./primitives";
import { verifyRotationDeletionEvidences } from "../rotation-deletion-evidence";
import type { KeyDirectoryPin } from "./types";
import type { SignedKeyDirectoryEnvelope } from "./types";
import { idbConditionalPut, idbGet, openIdb } from "@/shared/lib/storage/idb";

const DB_NAME = "refmd-security";
const DB_VERSION = 2;
const STORE_NAME = "key-directory-pins";
const DOCUMENT_STATE_STORE_NAME = "document-state-pins";
const MAX_LINEAGES_PER_SCOPE = 32;

export interface VerifiedKeyDirectoryLineage {
  checkpoints: SignedKeyDirectoryEnvelope[];
  events: SignedKeyDirectoryEnvelope[];
}

const verifiedKeyDirectoryLineages = new Map<string, Map<string, VerifiedKeyDirectoryLineage>>();

export { hashKeyDirectoryCheckpointEnvelope } from "./primitives";

export type { KeyDirectoryPin } from "./types";

export async function getKeyDirectoryPin(
  scopeKind: "user" | "workspace",
  scopeId: string,
): Promise<KeyDirectoryPin | null> {
  const db = await openSecurityDb();
  return (await idbGet<KeyDirectoryPin>(db, STORE_NAME, pinKey(scopeKind, scopeId))) ?? null;
}

export async function pinInitialKeyDirectoryCheckpoint(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  eventEnvelopes: Record<string, unknown>[];
  checkpointEnvelope: Record<string, unknown>;
}): Promise<void> {
  const checkpoint = assertEnvelope(params.checkpointEnvelope);
  await verifyInitialReplay(
    params.scopeKind,
    params.scopeId,
    params.eventEnvelopes.map(assertEnvelope),
    checkpoint,
  );
  const pin = pinFromCheckpoint(params.scopeKind, params.scopeId, checkpoint);
  if (pin.checkpointSequence !== 1) {
    throw new Error("initial_key_directory_checkpoint_sequence_invalid");
  }

  const db = await openSecurityDb();
  const wrote = await idbConditionalPut<KeyDirectoryPin>(
    db,
    STORE_NAME,
    pin.pinKey,
    pin,
    (existing) => {
      if (!existing) return true;
      return (
        existing.checkpointHash === pin.checkpointHash &&
        existing.eventHeadHash === pin.eventHeadHash &&
        existing.checkpointSequence === pin.checkpointSequence &&
        existing.eventHeadSequence === pin.eventHeadSequence
      );
    },
  );
  if (!wrote) throw new Error("key_directory_pin_conflict");
  rememberVerifiedKeyDirectoryLineage({
    scopeKind: params.scopeKind,
    scopeId: params.scopeId,
    checkpointEnvelope: checkpoint,
    checkpointAncestry: [],
    eventAncestry: params.eventEnvelopes.map(assertEnvelope),
  });
}

export async function installTransferredKeyDirectoryCheckpoint(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  checkpointEnvelope: Record<string, unknown>;
}): Promise<void> {
  const checkpoint = assertEnvelope(params.checkpointEnvelope);
  await verifyCheckpointSignatures(checkpoint, checkpoint.payload);
  const pin = pinFromCheckpoint(params.scopeKind, params.scopeId, checkpoint);
  const db = await openSecurityDb();
  const wrote = await idbConditionalPut<KeyDirectoryPin>(
    db,
    STORE_NAME,
    pin.pinKey,
    pin,
    (existing) => {
      if (!existing) return true;
      return (
        existing.checkpointHash === pin.checkpointHash &&
        existing.eventHeadHash === pin.eventHeadHash &&
        existing.checkpointSequence === pin.checkpointSequence &&
        existing.eventHeadSequence === pin.eventHeadSequence
      );
    },
  );
  if (!wrote) throw new Error("key_directory_pin_conflict");
  rememberVerifiedKeyDirectoryLineage({
    scopeKind: params.scopeKind,
    scopeId: params.scopeId,
    checkpointEnvelope: checkpoint,
    checkpointAncestry: [],
    eventAncestry: [],
  });
}

export async function advanceKeyDirectoryPinWithProof(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  checkpointEnvelope: Record<string, unknown>;
  checkpointAncestry: Record<string, unknown>[];
  eventAncestry: Record<string, unknown>[];
  authorityEventAncestry?: Record<string, unknown>[];
  rotationDeletionEvidences?: Record<string, unknown>[];
}): Promise<void> {
  const current = await getKeyDirectoryPin(params.scopeKind, params.scopeId);
  if (!current) throw new Error("key_directory_pin_required");

  const checkpoints = params.checkpointAncestry.map(assertEnvelope);
  const events = params.eventAncestry.map(assertEnvelope);
  const authorityEvents = (params.authorityEventAncestry ?? params.eventAncestry).map(
    assertEnvelope,
  );
  const eventAuthorityEvents = authorityEvents.filter(
    (event) =>
      numberField(event.payload.sequence, "event_sequence_invalid") <= current.eventHeadSequence,
  );
  const candidate = assertEnvelope(params.checkpointEnvelope);
  const candidatePin = pinFromCheckpoint(params.scopeKind, params.scopeId, candidate);

  if (
    candidatePin.checkpointSequence < current.checkpointSequence ||
    candidatePin.eventHeadSequence < current.eventHeadSequence
  ) {
    throw new Error("key_directory_checkpoint_rollback");
  }
  if (
    candidatePin.checkpointSequence === current.checkpointSequence ||
    candidatePin.eventHeadSequence === current.eventHeadSequence
  ) {
    if (
      candidatePin.checkpointSequence === current.checkpointSequence &&
      candidatePin.checkpointHash === current.checkpointHash &&
      candidatePin.eventHeadSequence === current.eventHeadSequence &&
      candidatePin.eventHeadHash === current.eventHeadHash
    ) {
      rememberVerifiedKeyDirectoryLineage({
        scopeKind: params.scopeKind,
        scopeId: params.scopeId,
        checkpointEnvelope: candidate,
        checkpointAncestry: checkpoints,
        eventAncestry: [...authorityEvents, ...events],
      });
      return;
    }
    throw new Error("key_directory_checkpoint_fork");
  }
  if (candidatePin.suitePolicyVersion < current.suitePolicyVersion) {
    throw new Error("key_directory_suite_policy_rollback");
  }
  if (candidatePin.minSuiteRank < current.minSuiteRank) {
    throw new Error("key_directory_min_suite_rank_rollback");
  }

  await verifyCheckpointAncestry(
    params.scopeKind,
    params.scopeId,
    current,
    checkpoints,
    candidate,
    events,
    authorityEvents,
  );
  await verifyEventAncestry(
    params.scopeKind,
    params.scopeId,
    current,
    events,
    candidate,
    checkpoints[0]!.payload,
    eventAuthorityEvents,
  );
  verifyRotationDeletionEvidences({
    scopeKind: params.scopeKind,
    scopeId: params.scopeId,
    events,
    evidences: params.rotationDeletionEvidences ?? [],
  });
  assertShareParticipantCheckpointAdvance(candidate, events, checkpoints[0]!.payload);

  const db = await openSecurityDb();
  const wrote = await idbConditionalPut<KeyDirectoryPin>(
    db,
    STORE_NAME,
    current.pinKey,
    candidatePin,
    (existing) =>
      !!existing &&
      existing.checkpointSequence === current.checkpointSequence &&
      existing.checkpointHash === current.checkpointHash &&
      existing.eventHeadSequence === current.eventHeadSequence &&
      existing.eventHeadHash === current.eventHeadHash,
  );
  if (!wrote) throw new Error("key_directory_pin_conflict");
  rememberVerifiedKeyDirectoryLineage({
    scopeKind: params.scopeKind,
    scopeId: params.scopeId,
    checkpointEnvelope: candidate,
    checkpointAncestry: checkpoints,
    eventAncestry: [...authorityEvents, ...events],
  });
}

export function rememberVerifiedKeyDirectoryLineage(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  checkpointEnvelope: SignedKeyDirectoryEnvelope;
  checkpointAncestry: SignedKeyDirectoryEnvelope[];
  eventAncestry: SignedKeyDirectoryEnvelope[];
}): void {
  const checkpoints = sortUniqueCheckpoints([
    ...params.checkpointAncestry,
    params.checkpointEnvelope,
  ]);
  const events = sortUniqueEvents(params.eventAncestry);
  const scopeKey = pinKey(params.scopeKind, params.scopeId);
  const lineages = verifiedKeyDirectoryLineages.get(scopeKey) ?? new Map();
  const lineageKey = checkpointLineageKey(params.checkpointEnvelope);
  const existing = lineages.get(lineageKey);
  lineages.set(lineageKey, {
    checkpoints: sortUniqueCheckpoints([...(existing?.checkpoints ?? []), ...checkpoints]),
    events: sortUniqueEvents([...(existing?.events ?? []), ...events]),
  });
  while (lineages.size > MAX_LINEAGES_PER_SCOPE) {
    const oldest = lineages.keys().next().value;
    if (!oldest) break;
    lineages.delete(oldest);
  }
  verifiedKeyDirectoryLineages.set(scopeKey, lineages);
}

export function lookupVerifiedKeyDirectoryLineage(
  scopeKind: "user" | "workspace",
  scopeId: string,
  pin: KeyDirectoryPin,
): VerifiedKeyDirectoryLineage | null {
  return (
    verifiedKeyDirectoryLineages
      .get(pinKey(scopeKind, scopeId))
      ?.get(`${pin.checkpointSequence}:${pin.checkpointHash}`) ?? null
  );
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

function openSecurityDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db, oldVersion) => {
    if (oldVersion < 1 && !db.objectStoreNames.contains(DOCUMENT_STATE_STORE_NAME)) {
      db.createObjectStore(DOCUMENT_STATE_STORE_NAME, { keyPath: "documentId" });
    }
    if (oldVersion < 2 && !db.objectStoreNames.contains(STORE_NAME)) {
      db.createObjectStore(STORE_NAME, { keyPath: "pinKey" });
    }
  });
}

function pinKey(scopeKind: "user" | "workspace", scopeId: string): string {
  return `${scopeKind}:${scopeId}`;
}
