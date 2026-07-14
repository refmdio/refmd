import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";

interface SignedKeyDirectoryEnvelope {
  payload: Record<string, unknown>;
  signatures: unknown[];
}

interface RotationDeletionEvidence {
  old_key_deleted_event_hash?: unknown;
  workspace_id?: unknown;
  document_id?: unknown;
  user_id?: unknown;
  rotation_kind?: unknown;
  scope_kind?: unknown;
  scope_id?: unknown;
  old_key_version?: unknown;
  completion_manifest?: unknown;
  deletion_manifest?: unknown;
  device_key_deletion_proofs?: unknown;
  wipe_required_device_ids?: unknown;
}

export function verifyRotationDeletionEvidences(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  events: SignedKeyDirectoryEnvelope[];
  evidences: Record<string, unknown>[];
}): void {
  const byEventHash = new Map<string, RotationDeletionEvidence>();
  const eventsByHash = new Map(params.events.map((event) => [eventHash(event), event]));
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
      eventsByHash,
    });
  }
}

function verifyRotationDeletionEvidence(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  event: SignedKeyDirectoryEnvelope;
  evidence: RotationDeletionEvidence | undefined;
  eventsByHash: Map<string, SignedKeyDirectoryEnvelope>;
}): void {
  const eventHashValue = eventHash(params.event);
  const evidence = params.evidence;
  if (!evidence) throw new Error("rotation_deletion_evidence_missing");
  const body = params.event.payload.body;
  if (!isRecord(body)) throw new Error("old_key_deleted_body_invalid");
  const manifest = evidence.deletion_manifest;
  if (!isRecord(manifest)) throw new Error("rotation_deletion_manifest_invalid");
  const manifestHash = blake3Base64Url(canonicalizeStrictBytes(manifest as StrictJsonValue));
  const eventScopeKind = stringField(body.scope_kind, "old_key_deleted_scope_invalid");
  const eventScopeId = stringField(body.scope_id, "old_key_deleted_scope_invalid");
  const belongsToDirectory =
    (params.scopeKind === "user" && eventScopeKind === "user" && eventScopeId === params.scopeId) ||
    (params.scopeKind === "workspace" &&
      ((eventScopeKind === "workspace" && eventScopeId === params.scopeId) ||
        (eventScopeKind === "document" && evidence.workspace_id === params.scopeId)));

  if (
    evidence.old_key_deleted_event_hash !== eventHashValue ||
    !belongsToDirectory ||
    body.rotation_kind !== evidence.rotation_kind ||
    eventScopeKind !== evidence.scope_kind ||
    eventScopeId !== evidence.scope_id ||
    body.deletion_manifest_hash !== manifestHash
  ) {
    throw new Error("rotation_deletion_evidence_mismatch");
  }

  if (!isRecord(evidence.device_key_deletion_proofs)) {
    throw new Error("rotation_deletion_proofs_missing");
  }

  if (evidence.rotation_kind === "identity") {
    verifyIdentityRotationDeletionEvidence(evidence, body, manifest, params.scopeId);
    return;
  }

  if (evidence.rotation_kind === "dek") {
    verifyDekRotationDeletionEvidence(
      evidence,
      body,
      manifest,
      params.scopeId,
      params.eventsByHash,
    );
    return;
  }

  if (
    evidence.rotation_kind !== "kek" ||
    evidence.workspace_id !== params.scopeId ||
    evidence.old_key_version !== body.old_key_version ||
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

  const { activeProofsHash, wipeRequiredHash } = deletionEvidenceSetHashes(evidence);
  if (
    manifest.active_device_deletion_proofs_hash !== activeProofsHash ||
    manifest.wipe_required_device_ids_hash !== wipeRequiredHash
  ) {
    throw new Error("rotation_deletion_manifest_mismatch");
  }
}

function verifyDekRotationDeletionEvidence(
  evidence: RotationDeletionEvidence,
  body: Record<string, unknown>,
  manifest: Record<string, unknown>,
  workspaceId: string,
  eventsByHash: Map<string, SignedKeyDirectoryEnvelope>,
): void {
  const { activeProofsHash, wipeRequiredHash } = deletionEvidenceSetHashes(evidence);
  const completionManifest = evidence.completion_manifest;
  if (!isRecord(completionManifest)) {
    throw new Error("rotation_completion_manifest_invalid");
  }
  const completedEventHash = stringField(
    manifest.rotation_completed_event_hash,
    "rotation_completion_event_hash_invalid",
  );
  const completedEvent = eventsByHash.get(completedEventHash);
  const completedBody = completedEvent?.payload.body;
  const completionManifestHash = blake3Base64Url(
    canonicalizeStrictBytes(completionManifest as StrictJsonValue),
  );
  if (
    evidence.workspace_id !== workspaceId ||
    evidence.document_id !== evidence.scope_id ||
    evidence.old_key_version !== body.old_key_version ||
    manifest.protocol !== "refmd.old-key-deletion-manifest" ||
    manifest.version !== 1 ||
    manifest.rotation_kind !== "dek" ||
    manifest.scope_kind !== "document" ||
    manifest.scope_id !== evidence.document_id ||
    manifest.old_key_version !== evidence.old_key_version ||
    !isRecord(completedBody) ||
    completedEvent?.payload.event_type !== "rotation_completed" ||
    completedBody.rotation_kind !== "dek" ||
    completedBody.scope_kind !== "document" ||
    completedBody.scope_id !== evidence.document_id ||
    completedBody.old_key_version !== evidence.old_key_version ||
    completedBody.completion_manifest_hash !== completionManifestHash ||
    completionManifest.protocol !== "refmd.rotation-completion-manifest" ||
    completionManifest.version !== 1 ||
    completionManifest.rotation_kind !== "dek" ||
    completionManifest.scope_kind !== "document" ||
    completionManifest.scope_id !== evidence.document_id ||
    completionManifest.old_key_version !== evidence.old_key_version ||
    !Array.isArray(completionManifest.new_key_records) ||
    !isRecord(completionManifest.rewritten_records) ||
    manifest.active_device_deletion_proofs_hash !== activeProofsHash ||
    manifest.wipe_required_device_ids_hash !== wipeRequiredHash ||
    typeof manifest.deleted_secret_ids_hash !== "string" ||
    typeof manifest.deleted_wrap_ids_hash !== "string" ||
    typeof manifest.server_rejects_old_key_uploads_after_sequence !== "number"
  ) {
    throw new Error("rotation_deletion_manifest_mismatch");
  }
}

function verifyIdentityRotationDeletionEvidence(
  evidence: RotationDeletionEvidence,
  body: Record<string, unknown>,
  manifest: Record<string, unknown>,
  scopeId: string,
): void {
  const proofsContainer = evidence.device_key_deletion_proofs as Record<string, unknown>;
  const proofs = proofsContainer.proofs;
  const wipeRequiredDeviceIds = evidence.wipe_required_device_ids;
  if (!Array.isArray(proofs) || !Array.isArray(wipeRequiredDeviceIds)) {
    throw new Error("rotation_deletion_proofs_missing");
  }

  const proofHashes = proofs
    .map((proof) => {
      if (!isRecord(proof) || !isRecord(proof.payload)) {
        throw new Error("rotation_deletion_proofs_missing");
      }
      return blake3Base64Url(canonicalizeStrictBytes(proof.payload as StrictJsonValue));
    })
    .sort();
  const activeProofsHash = blake3Base64Url(canonicalizeStrictBytes({ proof_hashes: proofHashes }));
  const wipeRequiredHash = blake3Base64Url(
    canonicalizeStrictBytes({
      device_ids: wipeRequiredDeviceIds.map((id) => stringField(id, "device_id_invalid")).sort(),
    }),
  );

  if (
    evidence.user_id !== scopeId ||
    typeof evidence.old_key_version !== "number" ||
    evidence.old_key_version < 1 ||
    manifest.rotation_kind !== "identity" ||
    manifest.scope_kind !== "user" ||
    manifest.scope_id !== scopeId ||
    manifest.old_identity_signing_key_id !== body.old_identity_signing_key_id ||
    manifest.old_identity_encryption_key_id !== body.old_identity_encryption_key_id ||
    manifest.new_identity_signing_key_id !== body.new_identity_signing_key_id ||
    manifest.rotation_completed_event_hash !== body.rotation_completed_event_hash ||
    manifest.active_identity_deletion_proofs_hash !== activeProofsHash ||
    manifest.wipe_required_device_ids_hash !== wipeRequiredHash ||
    typeof manifest.deleted_identity_secret_ids_hash !== "string" ||
    typeof manifest.server_rejects_old_identity_after_sequence !== "number"
  ) {
    throw new Error("rotation_deletion_manifest_mismatch");
  }
}

function deletionEvidenceSetHashes(evidence: RotationDeletionEvidence): {
  activeProofsHash: string;
  wipeRequiredHash: string;
} {
  const proofs = (evidence.device_key_deletion_proofs as Record<string, unknown>).proofs;
  const wipeRequiredDeviceIds = evidence.wipe_required_device_ids;
  if (!Array.isArray(proofs) || !Array.isArray(wipeRequiredDeviceIds)) {
    throw new Error("rotation_deletion_proofs_missing");
  }

  const proofHashes = proofs.map((proof) => {
    if (!isRecord(proof) || !isRecord(proof.payload)) {
      throw new Error("rotation_deletion_proofs_missing");
    }
    return blake3Base64Url(canonicalizeStrictBytes(proof.payload as StrictJsonValue));
  });
  const deviceIds = wipeRequiredDeviceIds.map((id) => stringField(id, "device_id_invalid"));
  if (
    new Set(proofHashes).size !== proofHashes.length ||
    new Set(deviceIds).size !== deviceIds.length
  ) {
    throw new Error("rotation_deletion_evidence_duplicate");
  }

  return {
    activeProofsHash: blake3Base64Url(
      canonicalizeStrictBytes({ proof_hashes: proofHashes.sort() }),
    ),
    wipeRequiredHash: blake3Base64Url(canonicalizeStrictBytes({ device_ids: deviceIds.sort() })),
  };
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
