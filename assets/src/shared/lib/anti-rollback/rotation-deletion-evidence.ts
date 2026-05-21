import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";

interface SignedKeyDirectoryEnvelope {
  payload: Record<string, unknown>;
  signatures: unknown[];
}

interface RotationDeletionEvidence {
  old_key_deleted_event_hash?: unknown;
  workspace_id?: unknown;
  rotation_kind?: unknown;
  scope_kind?: unknown;
  scope_id?: unknown;
  old_key_version?: unknown;
  deletion_manifest?: unknown;
  device_key_deletion_proofs?: unknown;
}

export function verifyRotationDeletionEvidences(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  events: SignedKeyDirectoryEnvelope[];
  evidences: Record<string, unknown>[];
}): void {
  const byEventHash = new Map<string, RotationDeletionEvidence>();
  for (const rawEvidence of params.evidences) {
    if (!isRecord(rawEvidence)) throw new Error("rotation_deletion_evidence_invalid");
    const evidence = rawEvidence as RotationDeletionEvidence;
    const eventHashValue = stringField(
      evidence.old_key_deleted_event_hash,
      "rotation_deletion_evidence_event_hash_invalid",
    );
    if (byEventHash.has(eventHashValue)) {
      throw new Error("rotation_deletion_evidence_duplicate");
    }
    byEventHash.set(eventHashValue, evidence);
  }

  for (const event of params.events) {
    if (event.payload.event_type !== "old_key_deleted") continue;
    verifyRotationDeletionEvidence({
      scopeKind: params.scopeKind,
      scopeId: params.scopeId,
      event,
      evidence: byEventHash.get(eventHash(event)),
    });
  }
}

function verifyRotationDeletionEvidence(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  event: SignedKeyDirectoryEnvelope;
  evidence: RotationDeletionEvidence | undefined;
}): void {
  const eventHashValue = eventHash(params.event);
  const evidence = params.evidence;
  if (!evidence) throw new Error("rotation_deletion_evidence_missing");
  const body = params.event.payload.body;
  if (!isRecord(body)) throw new Error("old_key_deleted_body_invalid");
  const manifest = evidence.deletion_manifest;
  if (!isRecord(manifest)) throw new Error("rotation_deletion_manifest_invalid");
  const manifestHash = blake3Base64Url(canonicalizeStrictBytes(manifest as StrictJsonValue));

  if (
    evidence.old_key_deleted_event_hash !== eventHashValue ||
    evidence.scope_kind !== params.scopeKind ||
    evidence.scope_id !== params.scopeId ||
    (typeof evidence.workspace_id === "string" && evidence.workspace_id !== params.scopeId) ||
    evidence.old_key_version !== body.old_key_version ||
    body.rotation_kind !== evidence.rotation_kind ||
    body.scope_kind !== evidence.scope_kind ||
    body.scope_id !== evidence.scope_id ||
    body.deletion_manifest_hash !== manifestHash
  ) {
    throw new Error("rotation_deletion_evidence_mismatch");
  }

  if (
    manifest.rotation_kind !== evidence.rotation_kind ||
    manifest.scope_kind !== evidence.scope_kind ||
    manifest.scope_id !== evidence.scope_id ||
    manifest.old_key_version !== evidence.old_key_version ||
    typeof manifest.rotation_completed_event_hash !== "string" ||
    typeof manifest.deleted_secret_ids_hash !== "string" ||
    typeof manifest.deleted_wrap_ids_hash !== "string" ||
    typeof manifest.active_device_deletion_proofs_hash !== "string" ||
    typeof manifest.wipe_required_device_ids_hash !== "string"
  ) {
    throw new Error("rotation_deletion_manifest_mismatch");
  }

  if (!isRecord(evidence.device_key_deletion_proofs)) {
    throw new Error("rotation_deletion_proofs_missing");
  }
}

function eventHash(envelope: SignedKeyDirectoryEnvelope): string {
  return blake3Base64Url(canonicalizeStrictBytes(envelope.payload as StrictJsonValue));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(value: unknown, error: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(error);
  }
  return value;
}
