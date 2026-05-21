import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";

export function buildEphemeralAuthorityBoundary(params: {
  workspaceId: string;
  publicData: Record<string, unknown>;
}): {
  workspace_event_head_sequence: number;
  workspace_event_head_hash: string;
  actor_active_proof_hash: string;
  document_permission_proof_hash: string;
  expires_event_sequence: number;
} {
  const { publicData } = params;
  const keyCheckpointSequence = numberField(
    publicData.keyCheckpointSequence,
    "key_checkpoint_sequence_invalid",
  );
  const keyCheckpointHash = stringField(
    publicData.keyCheckpointHash,
    "key_checkpoint_hash_invalid",
  );
  const workspaceEventHeadSequence = numberField(
    publicData.workspaceEventHeadSequence,
    "workspace_event_head_sequence_invalid",
  );
  const workspaceEventHeadHash = stringField(
    publicData.workspaceEventHeadHash,
    "workspace_event_head_hash_invalid",
  );
  const authorityKind = stringField(publicData.authorityKind, "authority_kind_invalid");
  const authorityId = stringField(publicData.authorityId, "authority_id_invalid");
  const authorityContextKey = stringField(
    publicData.authorityContextKey,
    "authority_context_key_invalid",
  );
  const authorityScopeId = stringField(publicData.authorityScopeId, "authority_scope_id_invalid");

  const actorActiveProof = {
    protocol: "refmd.editor-ephemeral-actor-active-proof",
    version: 1,
    owner_kind: stringField(publicData.ownerKind, "owner_kind_invalid"),
    owner_id: stringField(publicData.ownerId, "owner_id_invalid"),
    authority_kind: authorityKind,
    authority_id: authorityId,
    authority_context_key: authorityContextKey,
    key_checkpoint_sequence: keyCheckpointSequence,
    key_checkpoint_hash: keyCheckpointHash,
    signing_key_id: stringField(publicData.signingKeyId, "signing_key_id_invalid"),
  } as const;

  const permissionProof = {
    protocol: "refmd.document-permission-proof",
    version: 1,
    workspace_id: params.workspaceId,
    document_id: stringField(publicData.docId, "document_id_invalid"),
    authority_kind: authorityKind,
    authority_id: authorityId,
    authority_context_key: authorityContextKey,
    authority_scope_id: authorityScopeId,
    authority_permission_version: numberField(
      publicData.authorityPermissionVersion,
      "authority_permission_version_invalid",
    ),
    permission: "edit",
  } as const;

  return {
    workspace_event_head_sequence: workspaceEventHeadSequence,
    workspace_event_head_hash: workspaceEventHeadHash,
    actor_active_proof_hash: blake3Base64Url(
      canonicalizeStrictBytes(actorActiveProof as unknown as StrictJsonValue),
    ),
    document_permission_proof_hash: blake3Base64Url(
      canonicalizeStrictBytes(permissionProof as unknown as StrictJsonValue),
    ),
    expires_event_sequence: workspaceEventHeadSequence + 1,
  };
}

function numberField(value: unknown, reason: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(reason);
  }
  return value;
}

function stringField(value: unknown, reason: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(reason);
  }
  return value;
}
