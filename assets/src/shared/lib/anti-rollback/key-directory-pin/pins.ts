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
const DB_VERSION = 4;
const STORE_NAME = "key-directory-pins";
const DOCUMENT_STATE_STORE_NAME = "document-state-pins";
const VERIFIED_LINEAGE_STORE_NAME = "key-directory-verified-lineages";
const VERIFIED_LINEAGE_STORE_VERSION = 2;
const MAX_LINEAGES_PER_SCOPE = 32;
const MAX_VERIFIED_HASHES_PER_SCOPE = 512;
const MAX_VERIFIED_CHECKPOINT_BODIES_PER_SCOPE = 512;

export interface VerifiedKeyDirectoryLineage {
  checkpoints: SignedKeyDirectoryEnvelope[];
  events: SignedKeyDirectoryEnvelope[];
}

interface StoredVerifiedKeyDirectoryLineage {
  key: string;
  storeVersion?: number;
  checkpoints: SignedKeyDirectoryEnvelope[];
  events: SignedKeyDirectoryEnvelope[];
  updatedAt: number;
}

interface StoredVerifiedKeyDirectoryLineageIndex {
  key: string;
  storeVersion?: number;
  lineageKeys: string[];
  updatedAt: number;
}

const verifiedKeyDirectoryLineages = new Map<string, Map<string, VerifiedKeyDirectoryLineage>>();
const verifiedKeyDirectoryCheckpoints = new Map<string, Set<string>>();
const verifiedKeyDirectoryEvents = new Map<string, Set<string>>();
const verifiedKeyDirectoryCheckpointBodies = new Map<
  string,
  Map<string, SignedKeyDirectoryEnvelope>
>();
const verifiedKeyDirectoryEventBodies = new Map<string, Map<string, SignedKeyDirectoryEnvelope>>();

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
  const checkpoint = assertEnvelope(
    params.checkpointEnvelope as unknown as Record<string, unknown>,
  );
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
  const checkpoint = assertEnvelope(
    params.checkpointEnvelope as unknown as Record<string, unknown>,
  );
  await verifyCheckpointSignatures(checkpoint, checkpoint.payload);
  await installVerifiedTransferredKeyDirectoryCheckpoint({
    scopeKind: params.scopeKind,
    scopeId: params.scopeId,
    checkpointEnvelope: checkpoint,
  });
}

export async function installVerifiedTransferredKeyDirectoryCheckpoint(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  checkpointEnvelope: SignedKeyDirectoryEnvelope;
}): Promise<void> {
  const checkpoint = assertEnvelope(
    params.checkpointEnvelope as unknown as Record<string, unknown>,
  );
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
        checkpointAncestry: [],
        eventAncestry: [],
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

export async function verifyAndRememberKeyDirectoryLineageFromTrustedAnchor(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  trustedCheckpointEnvelope: Record<string, unknown>;
  checkpointEnvelope: Record<string, unknown>;
  checkpointAncestry: Record<string, unknown>[];
  eventAncestry: Record<string, unknown>[];
  authorityEventAncestry?: Record<string, unknown>[];
  rotationDeletionEvidences?: Record<string, unknown>[];
}): Promise<void> {
  const trustedAnchor = assertEnvelope(params.trustedCheckpointEnvelope);
  const trustedPin = pinFromCheckpoint(params.scopeKind, params.scopeId, trustedAnchor);
  const candidate = assertEnvelope(params.checkpointEnvelope);
  const candidatePin = pinFromCheckpoint(params.scopeKind, params.scopeId, candidate);
  const checkpoints = params.checkpointAncestry.map(assertEnvelope);
  const events = params.eventAncestry.map(assertEnvelope);
  const authorityEvents = (params.authorityEventAncestry ?? params.eventAncestry).map(
    assertEnvelope,
  );
  const eventAuthorityEvents = authorityEvents.filter(
    (event) =>
      numberField(event.payload.sequence, "event_sequence_invalid") <= trustedPin.eventHeadSequence,
  );

  if (
    candidatePin.checkpointSequence < trustedPin.checkpointSequence ||
    candidatePin.eventHeadSequence < trustedPin.eventHeadSequence
  ) {
    throw new Error("key_directory_checkpoint_rollback");
  }

  if (
    candidatePin.checkpointSequence === trustedPin.checkpointSequence &&
    candidatePin.checkpointHash === trustedPin.checkpointHash &&
    candidatePin.eventHeadSequence === trustedPin.eventHeadSequence &&
    candidatePin.eventHeadHash === trustedPin.eventHeadHash
  ) {
    rememberVerifiedKeyDirectoryLineage({
      scopeKind: params.scopeKind,
      scopeId: params.scopeId,
      checkpointEnvelope: candidate,
      checkpointAncestry: [],
      eventAncestry: [],
    });
    return;
  }

  const firstCheckpoint = checkpoints[0];
  if (!firstCheckpoint) throw new Error("key_directory_checkpoint_ancestry_required");
  const firstPin = pinFromCheckpoint(params.scopeKind, params.scopeId, firstCheckpoint);
  if (
    firstPin.checkpointSequence !== trustedPin.checkpointSequence ||
    firstPin.checkpointHash !== trustedPin.checkpointHash ||
    firstPin.eventHeadSequence !== trustedPin.eventHeadSequence ||
    firstPin.eventHeadHash !== trustedPin.eventHeadHash
  ) {
    throw new Error("key_directory_checkpoint_anchor_mismatch");
  }

  await verifyCheckpointAncestry(
    params.scopeKind,
    params.scopeId,
    trustedPin,
    checkpoints,
    candidate,
    events,
    eventAuthorityEvents,
  );
  await verifyEventAncestry(
    params.scopeKind,
    params.scopeId,
    trustedPin,
    events,
    candidate,
    trustedAnchor.payload,
    eventAuthorityEvents,
  );
  verifyRotationDeletionEvidences({
    scopeKind: params.scopeKind,
    scopeId: params.scopeId,
    events,
    evidences: params.rotationDeletionEvidences ?? [],
  });
  assertShareParticipantCheckpointAdvance(candidate, events, trustedAnchor.payload);
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
  const verifiedCheckpoints = verifiedKeyDirectoryCheckpoints.get(scopeKey) ?? new Set<string>();
  const verifiedCheckpointBodies = verifiedKeyDirectoryCheckpointBodies.get(scopeKey) ?? new Map();
  for (const checkpoint of checkpoints) {
    const key = checkpointLineageKey(checkpoint);
    verifiedCheckpoints.add(key);
    verifiedCheckpointBodies.set(key, checkpoint);
  }
  trimLineageKeySetToNewest(verifiedCheckpoints, MAX_VERIFIED_HASHES_PER_SCOPE);
  verifiedKeyDirectoryCheckpoints.set(scopeKey, verifiedCheckpoints);
  trimLineageKeyMapToNewest(verifiedCheckpointBodies, MAX_VERIFIED_CHECKPOINT_BODIES_PER_SCOPE);
  verifiedKeyDirectoryCheckpointBodies.set(scopeKey, verifiedCheckpointBodies);
  const verifiedEvents = verifiedKeyDirectoryEvents.get(scopeKey) ?? new Set<string>();
  const verifiedEventBodies = verifiedKeyDirectoryEventBodies.get(scopeKey) ?? new Map();
  for (const event of events) {
    const key = eventLineageKey(event);
    verifiedEvents.add(key);
    verifiedEventBodies.set(key, event);
  }
  trimLineageKeySetToNewest(verifiedEvents, MAX_VERIFIED_HASHES_PER_SCOPE);
  verifiedKeyDirectoryEvents.set(scopeKey, verifiedEvents);
  trimLineageKeyMapToNewest(verifiedEventBodies, MAX_VERIFIED_HASHES_PER_SCOPE);
  verifiedKeyDirectoryEventBodies.set(scopeKey, verifiedEventBodies);
  const lineages = verifiedKeyDirectoryLineages.get(scopeKey) ?? new Map();
  const lineageKey = checkpointLineageKey(params.checkpointEnvelope);
  const durableCheckpoints = sortUniqueCheckpoints([...(verifiedCheckpointBodies.values() ?? [])]);
  const durableEvents = sortUniqueEvents([...(verifiedEventBodies.values() ?? [])]);
  const lineage = {
    checkpoints: [params.checkpointEnvelope],
    events: [],
  };
  lineages.set(lineageKey, lineage);
  void persistVerifiedKeyDirectoryLineage(scopeKey, lineageKey, {
    ...lineage,
    checkpoints: durableCheckpoints,
    events: durableEvents,
  }).catch(() => {});
  const evictedLineageKeys: string[] = [];
  while (lineages.size > MAX_LINEAGES_PER_SCOPE) {
    const oldest = lineages.keys().next().value;
    if (!oldest) break;
    lineages.delete(oldest);
    evictedLineageKeys.push(oldest);
  }
  if (evictedLineageKeys.length > 0) {
    void deleteStoredVerifiedKeyDirectoryLineages(scopeKey, evictedLineageKeys).catch(() => {});
  }
  verifiedKeyDirectoryLineages.set(scopeKey, lineages);
}

function trimLineageKeySetToNewest(set: Set<string>, limit: number): void {
  if (set.size <= limit) return;
  for (const key of oldestLineageKeys(set, set.size - limit)) {
    set.delete(key);
  }
}

function trimLineageKeyMapToNewest<V>(map: Map<string, V>, limit: number): void {
  if (map.size <= limit) return;
  for (const key of oldestLineageKeys(map.keys(), map.size - limit)) {
    map.delete(key);
  }
}

function oldestLineageKeys(keys: Iterable<string>, count: number): string[] {
  return [...keys].sort((a, b) => lineageKeySequence(a) - lineageKeySequence(b)).slice(0, count);
}

function lineageKeySequence(key: string): number {
  const sequence = Number(key.slice(0, key.indexOf(":")));
  return Number.isSafeInteger(sequence) ? sequence : 0;
}

export async function hydrateVerifiedKeyDirectoryLineage(
  scopeKind: "user" | "workspace",
  scopeId: string,
  pin: KeyDirectoryPin,
): Promise<VerifiedKeyDirectoryLineage | null> {
  const existing = lookupVerifiedKeyDirectoryLineage(scopeKind, scopeId, pin);
  if (existing) return existing;

  const scopeKey = pinKey(scopeKind, scopeId);
  const lineageKey = `${pin.checkpointSequence}:${pin.checkpointHash}`;
  const stored = await getStoredVerifiedKeyDirectoryLineage(scopeKey, lineageKey);
  if (!stored) return null;

  const checkpoints = sortUniqueCheckpoints(
    stored.checkpoints.map((checkpoint) =>
      assertEnvelope(checkpoint as unknown as Record<string, unknown>),
    ),
  );
  const events = sortUniqueEvents(
    stored.events.map((event) => assertEnvelope(event as unknown as Record<string, unknown>)),
  );
  const checkpointEnvelope = checkpoints.find((checkpoint) => {
    const sequence = numberField(checkpoint.payload.sequence, "checkpoint_sequence_invalid");
    return sequence === pin.checkpointSequence && checkpointHash(checkpoint) === pin.checkpointHash;
  });
  if (!checkpointEnvelope) return null;

  rememberVerifiedKeyDirectoryLineage({
    scopeKind,
    scopeId,
    checkpointEnvelope,
    checkpointAncestry: checkpoints.filter((checkpoint) => checkpoint !== checkpointEnvelope),
    eventAncestry: events,
  });
  return lookupVerifiedKeyDirectoryLineage(scopeKind, scopeId, pin);
}

export function hasVerifiedKeyDirectoryCheckpoint(
  scopeKind: "user" | "workspace",
  scopeId: string,
  sequence: number,
  hash: string,
): boolean {
  return (
    verifiedKeyDirectoryCheckpoints.get(pinKey(scopeKind, scopeId))?.has(`${sequence}:${hash}`) ===
    true
  );
}

export function hasVerifiedKeyDirectoryEvent(
  scopeKind: "user" | "workspace",
  scopeId: string,
  sequence: number,
  hash: string,
): boolean {
  return (
    verifiedKeyDirectoryEvents.get(pinKey(scopeKind, scopeId))?.has(`${sequence}:${hash}`) === true
  );
}

export function lookupVerifiedKeyDirectoryEventBodies(
  scopeKind: "user" | "workspace",
  scopeId: string,
): SignedKeyDirectoryEnvelope[] {
  return sortUniqueEvents([
    ...(verifiedKeyDirectoryEventBodies.get(pinKey(scopeKind, scopeId))?.values() ?? []),
  ]);
}

export function lookupVerifiedKeyDirectoryCheckpointBodies(
  scopeKind: "user" | "workspace",
  scopeId: string,
): SignedKeyDirectoryEnvelope[] {
  return sortUniqueCheckpoints([
    ...(verifiedKeyDirectoryCheckpointBodies.get(pinKey(scopeKind, scopeId))?.values() ?? []),
  ]);
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

function persistVerifiedKeyDirectoryLineage(
  scopeKey: string,
  lineageKey: string,
  lineage: VerifiedKeyDirectoryLineage,
): Promise<void> {
  return new Promise((resolve, reject) => {
    openSecurityDb()
      .then((db) => {
        const tx = db.transaction(VERIFIED_LINEAGE_STORE_NAME, "readwrite");
        const store = tx.objectStore(VERIFIED_LINEAGE_STORE_NAME);
        const updatedAt = Date.now();
        const lineageStoreKey = storedLineageKey(scopeKey, lineageKey);
        const lineageRequest = store.get(lineageStoreKey);
        const indexRequest = store.get(storedLineageIndexKey(scopeKey));
        lineageRequest.onsuccess = () => {
          const existing = lineageRequest.result as StoredVerifiedKeyDirectoryLineage | undefined;
          const events =
            existing?.storeVersion === VERIFIED_LINEAGE_STORE_VERSION &&
            Array.isArray(existing.events)
              ? sortUniqueEvents([
                  ...existing.events.map((event) =>
                    assertEnvelope(event as unknown as Record<string, unknown>),
                  ),
                  ...lineage.events,
                ]).slice(-MAX_VERIFIED_HASHES_PER_SCOPE)
              : lineage.events;
          store.put({
            key: lineageStoreKey,
            storeVersion: VERIFIED_LINEAGE_STORE_VERSION,
            checkpoints: lineage.checkpoints,
            events,
            updatedAt,
          } satisfies StoredVerifiedKeyDirectoryLineage);
        };
        lineageRequest.onerror = () => {
          reject(lineageRequest.error);
        };
        indexRequest.onsuccess = () => {
          const existing = indexRequest.result as
            | StoredVerifiedKeyDirectoryLineageIndex
            | undefined;
          const lineageKeys =
            existing?.storeVersion === VERIFIED_LINEAGE_STORE_VERSION &&
            Array.isArray(existing.lineageKeys)
              ? existing.lineageKeys.filter((key) => typeof key === "string" && key !== lineageKey)
              : [];
          lineageKeys.push(lineageKey);
          const evictedCount = Math.max(0, lineageKeys.length - MAX_LINEAGES_PER_SCOPE);
          const evicted = lineageKeys.splice(0, evictedCount);
          for (const evictedLineageKey of evicted) {
            store.delete(storedLineageKey(scopeKey, evictedLineageKey));
          }
          store.put({
            key: storedLineageIndexKey(scopeKey),
            storeVersion: VERIFIED_LINEAGE_STORE_VERSION,
            lineageKeys,
            updatedAt,
          } satisfies StoredVerifiedKeyDirectoryLineageIndex);
        };
        indexRequest.onerror = () => {
          reject(indexRequest.error);
        };
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      })
      .catch(reject);
  });
}

function deleteStoredVerifiedKeyDirectoryLineages(
  scopeKey: string,
  lineageKeys: string[],
): Promise<void> {
  return new Promise((resolve, reject) => {
    openSecurityDb()
      .then((db) => {
        const tx = db.transaction(VERIFIED_LINEAGE_STORE_NAME, "readwrite");
        const store = tx.objectStore(VERIFIED_LINEAGE_STORE_NAME);
        for (const lineageKey of lineageKeys) {
          store.delete(storedLineageKey(scopeKey, lineageKey));
        }
        const indexRequest = store.get(storedLineageIndexKey(scopeKey));
        indexRequest.onsuccess = () => {
          const existing = indexRequest.result as
            | StoredVerifiedKeyDirectoryLineageIndex
            | undefined;
          if (
            existing?.storeVersion !== VERIFIED_LINEAGE_STORE_VERSION ||
            !Array.isArray(existing.lineageKeys)
          ) {
            return;
          }
          const removed = new Set(lineageKeys);
          const remaining = existing.lineageKeys.filter(
            (lineageKey) => typeof lineageKey === "string" && !removed.has(lineageKey),
          );
          if (remaining.length === 0) {
            store.delete(storedLineageIndexKey(scopeKey));
            return;
          }
          store.put({
            key: storedLineageIndexKey(scopeKey),
            storeVersion: VERIFIED_LINEAGE_STORE_VERSION,
            lineageKeys: remaining,
            updatedAt: Date.now(),
          } satisfies StoredVerifiedKeyDirectoryLineageIndex);
        };
        indexRequest.onerror = () => {
          reject(indexRequest.error);
        };
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      })
      .catch(reject);
  });
}

async function getStoredVerifiedKeyDirectoryLineage(
  scopeKey: string,
  lineageKey: string,
): Promise<StoredVerifiedKeyDirectoryLineage | null> {
  try {
    const db = await openSecurityDb();
    const stored =
      (await idbGet<StoredVerifiedKeyDirectoryLineage>(
        db,
        VERIFIED_LINEAGE_STORE_NAME,
        storedLineageKey(scopeKey, lineageKey),
      )) ?? null;
    if (stored?.storeVersion !== VERIFIED_LINEAGE_STORE_VERSION) return null;
    return stored;
  } catch {
    return null;
  }
}

function storedLineageKey(scopeKey: string, lineageKey: string): string {
  return `${scopeKey}:${lineageKey}`;
}

function storedLineageIndexKey(scopeKey: string): string {
  return `${scopeKey}:__lineage_index__`;
}

function openSecurityDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db, oldVersion) => {
    if (oldVersion < 1 && !db.objectStoreNames.contains(DOCUMENT_STATE_STORE_NAME)) {
      db.createObjectStore(DOCUMENT_STATE_STORE_NAME, { keyPath: "documentId" });
    }
    if (oldVersion < 2 && !db.objectStoreNames.contains(STORE_NAME)) {
      db.createObjectStore(STORE_NAME, { keyPath: "pinKey" });
    }
    if (oldVersion < 4 && db.objectStoreNames.contains(VERIFIED_LINEAGE_STORE_NAME)) {
      db.deleteObjectStore(VERIFIED_LINEAGE_STORE_NAME);
    }
    if (!db.objectStoreNames.contains(VERIFIED_LINEAGE_STORE_NAME)) {
      db.createObjectStore(VERIFIED_LINEAGE_STORE_NAME, { keyPath: "key" });
    }
  });
}

function pinKey(scopeKind: "user" | "workspace", scopeId: string): string {
  return `${scopeKind}:${scopeId}`;
}
