import { deviceState } from "@/entities/session";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import {
  getKeyDirectoryPin,
  lookupVerifiedKeyDirectoryCheckpointBodies,
  lookupVerifiedKeyDirectoryEventBodies,
  lookupVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  assertEnvelope,
  assertKeyEntryActiveAtSequence,
  eventHash,
  isRecord,
  numberField,
  signingKeyMaterialById,
  stringField,
} from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import { verifyInitialReplay } from "@/shared/lib/anti-rollback/key-directory-pin/verification";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import type { PluginRuntimeApprovalAuthorityVerification } from "./runtime-types";

export async function verifyPluginRuntimeApprovalAuthorityFromKeyDirectory({
  approvalSubject,
  authority,
  proof,
}: PluginRuntimeApprovalAuthorityVerification): Promise<void> {
  const device = deviceState();
  if (!device?.deviceId) throw new Error("trusted_signer_device_required");
  const { scopeKind, scopeId } = approvalAuthorityScope(authority, approvalSubject);

  const proofLineage = await verifiedApprovalAuthorityLineageFromProof(proof, authority);
  if (proofLineage) {
    assertApprovalAuthorityFromVerifiedLineage(
      authority,
      proofLineage.checkpoint.payload,
      proofLineage.events,
    );
    return;
  }

  const directory = await fetchVerifiedKeyDirectory({
    scopeKind,
    scopeId,
    rrpDeviceId: device.deviceId,
  });

  const pin = await getKeyDirectoryPin(scopeKind, scopeId);
  if (!pin) throw new Error("approval_authority_lineage_required");

  const lineage = lookupVerifiedKeyDirectoryLineage(scopeKind, scopeId, pin);
  if (!lineage) throw new Error("approval_authority_lineage_required");

  const authorityCheckpointSequence = numberField(
    authority.checkpoint_sequence,
    "approval_authority_checkpoint_sequence_invalid",
  );
  const authorityCheckpointHash = stringField(
    authority.checkpoint_hash,
    "approval_authority_checkpoint_hash_invalid",
  );
  const checkpoint = [
    directory.checkpoint,
    ...lookupVerifiedKeyDirectoryCheckpointBodies(scopeKind, scopeId),
    ...lineage.checkpoints,
  ].find(
    (entry) =>
      numberField(entry.payload.sequence, "checkpoint_sequence_invalid") ===
        authorityCheckpointSequence &&
      blake3Base64Url(canonicalizeStrictBytes(entry.payload as StrictJsonValue)) ===
        authorityCheckpointHash,
  );
  if (!checkpoint) throw new Error("approval_authority_checkpoint_required");

  assertApprovalAuthorityFromVerifiedLineage(authority, checkpoint.payload, [
    ...lineage.events,
    ...lookupVerifiedKeyDirectoryEventBodies(scopeKind, scopeId),
  ]);
}

async function verifiedApprovalAuthorityLineageFromProof(
  proof: PluginRuntimeApprovalAuthorityVerification["proof"],
  authority: Record<string, StrictJsonValue>,
): Promise<{
  checkpoint: SignedKeyDirectoryEnvelope;
  events: SignedKeyDirectoryEnvelope[];
} | null> {
  if (
    proof.approval_authority_checkpoint === undefined ||
    proof.approval_authority_event_ancestry === undefined
  ) {
    return null;
  }
  if (!isRecord(proof.approval_authority_checkpoint)) {
    throw new Error("approval_authority_checkpoint_required");
  }
  if (!Array.isArray(proof.approval_authority_event_ancestry)) {
    throw new Error("approval_authority_event_head_required");
  }

  const scopeKind = authorityScopeKind(authority);
  const scopeId = authorityScopeId(authority, scopeKind);
  const checkpoint = assertEnvelope(proof.approval_authority_checkpoint);
  const events = proof.approval_authority_event_ancestry.map((entry) => {
    if (!isRecord(entry)) throw new Error("approval_authority_event_head_required");
    return assertEnvelope(entry);
  });

  const checkpointSequence = numberField(
    checkpoint.payload.sequence,
    "approval_authority_checkpoint_sequence_invalid",
  );
  const authorityCheckpointSequence = numberField(
    authority.checkpoint_sequence,
    "approval_authority_checkpoint_sequence_invalid",
  );
  const authorityCheckpointHash = stringField(
    authority.checkpoint_hash,
    "approval_authority_checkpoint_hash_invalid",
  );
  if (
    checkpointSequence !== authorityCheckpointSequence ||
    blake3Base64Url(canonicalizeStrictBytes(checkpoint.payload as StrictJsonValue)) !==
      authorityCheckpointHash
  ) {
    throw new Error("approval_authority_checkpoint_required");
  }

  await verifyInitialReplay(scopeKind, scopeId, events, checkpoint);
  return { checkpoint, events };
}

export function assertApprovalAuthorityFromVerifiedLineage(
  authority: Record<string, StrictJsonValue>,
  checkpointPayload: Record<string, unknown>,
  events: readonly SignedKeyDirectoryEnvelope[],
): void {
  const scopeKind = authorityScopeKind(authority);
  const scopeId = authorityScopeId(authority, scopeKind);
  const userId = stringField(authority.user_id, "approval_authority_user_invalid");
  const deviceId = stringField(authority.device_id, "approval_authority_device_invalid");
  const signingKeyId = stringField(
    authority.signing_key_id,
    "approval_authority_signing_key_invalid",
  );
  const eventHeadSequence = nonNegativeIntegerField(
    authority.event_head_sequence,
    "approval_authority_event_head_sequence_invalid",
  );
  const eventHeadHash = stringField(
    authority.event_head_hash,
    "approval_authority_event_head_hash_invalid",
  );

  const coveredHead = requireUnknownRecord(
    checkpointPayload.covered_event_head,
    "approval_authority_checkpoint_head_invalid",
  );
  if (
    numberField(coveredHead.head_sequence, "approval_authority_checkpoint_head_invalid") !==
      eventHeadSequence ||
    stringField(coveredHead.head_hash, "approval_authority_checkpoint_head_invalid") !==
      eventHeadHash
  ) {
    throw new Error("approval_authority_checkpoint_head_mismatch");
  }

  const memberRoles = new Map<string, string>();
  const sortedEvents = [...events].sort(
    (left, right) =>
      numberField(left.payload.sequence, "event_sequence_invalid") -
      numberField(right.payload.sequence, "event_sequence_invalid"),
  );
  let eventHeadFound = false;

  for (const event of sortedEvents) {
    const sequence = numberField(event.payload.sequence, "event_sequence_invalid");
    if (sequence > eventHeadSequence) break;
    if (event.payload.scope_kind !== scopeKind || event.payload.scope_id !== scopeId) {
      continue;
    }
    if (sequence === eventHeadSequence) {
      eventHeadFound = eventHash(event) === eventHeadHash;
    }
    if (scopeKind === "user") continue;
    const body = isRecord(event.payload.body) ? event.payload.body : {};
    if (event.payload.event_type === "member_added") {
      memberRoles.set(
        stringField(body.user_id, "approval_authority_member_user_invalid"),
        stringField(body.base_role, "approval_authority_member_role_invalid"),
      );
    } else if (event.payload.event_type === "member_role_changed") {
      memberRoles.set(
        stringField(body.user_id, "approval_authority_member_user_invalid"),
        stringField(body.base_role, "approval_authority_member_role_invalid"),
      );
    } else if (event.payload.event_type === "member_removed") {
      memberRoles.delete(stringField(body.user_id, "approval_authority_member_user_invalid"));
    }
  }

  if (!eventHeadFound) throw new Error("approval_authority_event_head_required");
  if (scopeKind === "workspace") {
    const role = memberRoles.get(userId);
    if (role !== "owner" && role !== "admin") {
      throw new Error("approval_authority_role_forbidden");
    }
  } else if (userId !== scopeId) {
    throw new Error("approval_authority_user_mismatch");
  }

  const keyMaterial = signingKeyMaterialById(checkpointPayload).get(signingKeyId);
  if (!keyMaterial) throw new Error("approval_authority_signing_key_untrusted");
  if (keyMaterial.owner_kind !== "device" || keyMaterial.owner_id !== deviceId) {
    throw new Error("approval_authority_signing_key_owner_mismatch");
  }
  assertKeyEntryActiveAtSequence(checkpointPayload, signingKeyId, eventHeadSequence);
}

function approvalAuthorityScope(
  authority: Record<string, StrictJsonValue>,
  approvalSubject: Record<string, StrictJsonValue>,
): { scopeKind: "user" | "workspace"; scopeId: string } {
  const scopeKind = authorityScopeKind(authority);
  if (approvalSubject.owner_scope_kind !== scopeKind) {
    throw new Error("approval_authority_scope_mismatch");
  }
  const scopeId = authorityScopeId(authority, scopeKind);
  if (scopeKind === "user" && approvalSubject.owner_user_id !== scopeId) {
    throw new Error("approval_authority_user_mismatch");
  }
  if (scopeKind === "workspace" && approvalSubject.owner_workspace_id !== scopeId) {
    throw new Error("approval_authority_workspace_mismatch");
  }
  return { scopeKind, scopeId };
}

function authorityScopeKind(authority: Record<string, StrictJsonValue>): "user" | "workspace" {
  if (authority.scope_kind === "workspace") return "workspace";
  if (authority.scope_kind === "user") return "user";
  throw new Error("approval_authority_scope_mismatch");
}

function authorityScopeId(
  authority: Record<string, StrictJsonValue>,
  scopeKind: "user" | "workspace",
): string {
  return scopeKind === "workspace"
    ? stringField(authority.workspace_id, "approval_authority_workspace_invalid")
    : stringField(authority.owner_user_id, "approval_authority_user_invalid");
}

function requireUnknownRecord(value: unknown, error: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(error);
  return value;
}

function nonNegativeIntegerField(value: unknown, error: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(error);
  }
  return value;
}
