import { assertEnvelope, checkpointHash } from "./key-directory-pin/primitives";
import { AUDIT_CHECKPOINT_PIN_STORE_NAME, openSecurityDb } from "./security-db";
import { idbConditionalPut, idbGet } from "@/shared/lib/storage/idb";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  hasVerifiedKeyDirectoryCheckpoint,
  lookupVerifiedKeyDirectoryCheckpointBodies,
} from "./key-directory-pin/pins";

export interface AuditCheckpoint {
  chain_scope: string;
  sequence: number;
  event_hash: string;
  authority_checkpoint: Record<string, unknown> | null;
  ancestry: Record<string, unknown>[];
}

export interface AuditCheckpointPin {
  chainScope: string;
  sequence: number;
  eventHash: string;
  authorityCheckpointHash: string;
  observedAt: number;
}

export async function getAuditCheckpointPin(
  chainScope: string,
): Promise<AuditCheckpointPin | null> {
  const db = await openSecurityDb();
  return (
    (await idbGet<AuditCheckpointPin>(db, AUDIT_CHECKPOINT_PIN_STORE_NAME, chainScope)) ?? null
  );
}

export async function installTransferredAuditCheckpointPin(value: unknown): Promise<void> {
  const pin = assertAuditCheckpointPin(value);
  const db = await openSecurityDb();
  const wrote = await idbConditionalPut<AuditCheckpointPin>(
    db,
    AUDIT_CHECKPOINT_PIN_STORE_NAME,
    pin.chainScope,
    { ...pin, observedAt: Date.now() },
    (existing) =>
      !existing ||
      (existing.sequence === pin.sequence &&
        existing.eventHash === pin.eventHash &&
        existing.authorityCheckpointHash === pin.authorityCheckpointHash),
  );
  if (!wrote) throw new Error("audit_checkpoint_transfer_conflict");
}

export function assertTransferredWorkspaceAuditPins(
  workspaceIds: string[],
  value: unknown,
): AuditCheckpointPin[] {
  if (!Array.isArray(value)) {
    throw new Error("trust_state_bundle_workspace_audit_pins_invalid");
  }
  const expectedScopes = new Set(workspaceIds.map((workspaceId) => `workspace:${workspaceId}`));
  if (expectedScopes.size !== workspaceIds.length) {
    throw new Error("trust_state_bundle_workspace_checkpoints_invalid");
  }

  const pins = value.map(assertAuditCheckpointPin);
  const actualScopes = new Set(pins.map((pin) => pin.chainScope));
  if (
    actualScopes.size !== pins.length ||
    actualScopes.size !== expectedScopes.size ||
    [...expectedScopes].some((scope) => !actualScopes.has(scope))
  ) {
    throw new Error("trust_state_bundle_workspace_audit_pins_mismatch");
  }
  return pins;
}

export async function verifyAndPinAuditCheckpoint(value: unknown): Promise<AuditCheckpointPin> {
  const pin = await verifyAuditCheckpointCandidate(value);
  const db = await openSecurityDb();
  const wrote = await idbConditionalPut<AuditCheckpointPin>(
    db,
    AUDIT_CHECKPOINT_PIN_STORE_NAME,
    pin.chainScope,
    pin,
    (existing) => {
      if (!existing) return true;
      if (pin.sequence < existing.sequence) return false;
      if (pin.sequence === existing.sequence) return pin.eventHash === existing.eventHash;
      return true;
    },
  );
  if (!wrote) throw new Error("audit_checkpoint_rollback_or_fork");
  return pin;
}

export async function verifyAuditCheckpointCandidate(value: unknown): Promise<AuditCheckpointPin> {
  const checkpoint = assertAuditCheckpoint(value);
  const [scopeKind, scopeId] = checkpoint.chain_scope.split(":", 2);
  if ((scopeKind !== "user" && scopeKind !== "workspace") || !scopeId) {
    throw new Error("audit_checkpoint_scope_unsupported");
  }
  if (!checkpoint.authority_checkpoint) {
    throw new Error("audit_checkpoint_authority_missing");
  }

  const authority = assertEnvelope(checkpoint.authority_checkpoint);
  if (authority.payload.scope_kind !== scopeKind || authority.payload.scope_id !== scopeId) {
    throw new Error("audit_checkpoint_authority_scope_mismatch");
  }
  const authorityCheckpointHash = checkpointHash(authority);
  const authoritySequence = authority.payload.sequence;
  if (
    !Number.isSafeInteger(authoritySequence) ||
    !hasVerifiedKeyDirectoryCheckpoint(
      scopeKind,
      scopeId,
      authoritySequence as number,
      authorityCheckpointHash,
    )
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
  const existing = await getAuditCheckpointPin(checkpoint.chain_scope);
  if (
    existing &&
    (checkpoint.sequence < existing.sequence ||
      (checkpoint.sequence === existing.sequence && checkpoint.event_hash !== existing.eventHash))
  ) {
    throw new Error("audit_checkpoint_rollback_or_fork");
  }
  if (existing && existing.authorityCheckpointHash !== authorityCheckpointHash) {
    assertAuditAuthorityCheckpointAdvance(
      scopeKind,
      scopeId,
      existing.authorityCheckpointHash,
      authority,
    );
  }
  verifyAuditAncestry(checkpoint, existing);

  const pin: AuditCheckpointPin = {
    chainScope: checkpoint.chain_scope,
    sequence: checkpoint.sequence,
    eventHash: checkpoint.event_hash,
    authorityCheckpointHash,
    observedAt: Date.now(),
  };
  return pin;
}

function assertAuditAuthorityCheckpointAdvance(
  scopeKind: "user" | "workspace",
  scopeId: string,
  pinnedAuthorityHash: string,
  candidate: ReturnType<typeof assertEnvelope>,
): void {
  const candidateHash = checkpointHash(candidate);
  const checkpoints = lookupVerifiedKeyDirectoryCheckpointBodies(scopeKind, scopeId);
  const anchorIndex = checkpoints.findIndex(
    (checkpoint) => checkpointHash(checkpoint) === pinnedAuthorityHash,
  );
  const candidateIndex = checkpoints.findIndex(
    (checkpoint) => checkpointHash(checkpoint) === candidateHash,
  );
  if (anchorIndex < 0 || candidateIndex <= anchorIndex) {
    throw new Error("audit_checkpoint_authority_replacement");
  }

  for (let index = anchorIndex + 1; index <= candidateIndex; index += 1) {
    const previous = checkpoints[index - 1]!;
    const next = checkpoints[index]!;
    const previousSequence = previous.payload.sequence;
    const nextSequence = next.payload.sequence;
    if (
      !Number.isSafeInteger(previousSequence) ||
      !Number.isSafeInteger(nextSequence) ||
      nextSequence !== (previousSequence as number) + 1 ||
      next.payload.previous_checkpoint_hash !== checkpointHash(previous)
    ) {
      throw new Error("audit_checkpoint_authority_replacement");
    }
  }
}

function assertAuditCheckpoint(value: unknown): AuditCheckpoint {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("audit_checkpoint_missing");
  }
  const record = value as Record<string, unknown>;
  const sequence = record.sequence;
  if (!Number.isSafeInteger(sequence) || (sequence as number) < 1) {
    throw new Error("audit_checkpoint_sequence_invalid");
  }
  return {
    chain_scope: requiredString(record.chain_scope, "audit_checkpoint_scope_invalid"),
    sequence: sequence as number,
    event_hash: requiredHash(record.event_hash),
    authority_checkpoint:
      record.authority_checkpoint && typeof record.authority_checkpoint === "object"
        ? (record.authority_checkpoint as Record<string, unknown>)
        : null,
    ancestry: Array.isArray(record.ancestry)
      ? record.ancestry.map((entry) => requiredRecord(entry, "audit_checkpoint_ancestry_invalid"))
      : [],
  };
}

function assertAuditCheckpointPin(value: unknown): AuditCheckpointPin {
  const record = requiredRecord(value, "audit_checkpoint_pin_invalid");
  const sequence = record.sequence;
  if (!Number.isSafeInteger(sequence) || (sequence as number) < 1) {
    throw new Error("audit_checkpoint_pin_invalid");
  }
  return {
    chainScope: requiredString(record.chainScope, "audit_checkpoint_pin_invalid"),
    sequence: sequence as number,
    eventHash: requiredHash(record.eventHash),
    authorityCheckpointHash: requiredHash(record.authorityCheckpointHash),
    observedAt: 0,
  };
}

function verifyAuditAncestry(
  checkpoint: AuditCheckpoint,
  existing: AuditCheckpointPin | null,
): void {
  let sequence = existing?.sequence ?? 0;
  let previousHash = existing?.eventHash ?? null;
  const events = checkpoint.ancestry.filter((event) => Number(event.sequence) > sequence);
  if (events.length === 0 && checkpoint.sequence !== sequence) {
    throw new Error("audit_checkpoint_ancestry_missing");
  }
  for (const event of events) {
    const candidateSequence = event.sequence;
    if (candidateSequence !== sequence + 1 || event.previous_event_hash !== previousHash) {
      throw new Error("audit_checkpoint_ancestry_invalid");
    }
    const eventHash = requiredHash(event.event_hash);
    const preimage = { ...event };
    delete preimage.event_hash;
    if (
      blake3Base64Url(canonicalizeStrictBytes(compact(preimage) as StrictJsonValue)) !== eventHash
    ) {
      throw new Error("audit_checkpoint_ancestry_invalid");
    }
    sequence = candidateSequence as number;
    previousHash = eventHash;
  }
  if (sequence !== checkpoint.sequence || previousHash !== checkpoint.event_hash) {
    throw new Error("audit_checkpoint_ancestry_invalid");
  }
}

function compact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(compact);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== null && nested !== undefined)
      .map(([key, nested]) => [key, compact(nested)]),
  );
}

function requiredRecord(value: unknown, code: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

function requiredHash(value: unknown): string {
  const hash = requiredString(value, "audit_checkpoint_hash_invalid");
  if (!/^[A-Za-z0-9_-]{43}$/.test(hash)) throw new Error("audit_checkpoint_hash_invalid");
  return hash;
}

function requiredString(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}
