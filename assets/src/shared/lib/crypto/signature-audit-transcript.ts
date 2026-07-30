import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { getActiveSigningSurface } from "./signing-surface";
import { transcriptBase, type SigningOwnerKind } from "./signature-transcript-core";
import { CURRENT_PROTOCOL_VERSION } from "./suite";

export type AuditCheckpointVariant =
  | "user_identity"
  | "user_device"
  | "workspace_device"
  | "workspace_guest_device";

export function buildAuditCheckpointTranscript(params: {
  variant: AuditCheckpointVariant;
  ownerKind: SigningOwnerKind;
  ownerId: string;
  payload: StrictJsonValue;
}): StrictJsonValue {
  const payload = assertAuditCheckpointPayload(params.variant, params.payload);
  const surface = getActiveSigningSurface("audit_checkpoint", params.variant);

  return transcriptBase("audit_checkpoint", surface, params.ownerKind, params.ownerId, {
    subject_protocol: "refmd.signed-audit-checkpoint",
    subject_version: CURRENT_PROTOCOL_VERSION,
    subject_hash: auditCheckpointHash(params.payload),
    checkpoint: {
      chain_scope_kind: payload.chain_scope_kind,
      chain_scope_id: payload.chain_scope_id,
      sequence: payload.sequence,
      event_hash: payload.event_hash,
      ...(isGenesisCheckpoint(payload)
        ? {}
        : {
            previous_signed_checkpoint_sequence: payload.previous_signed_checkpoint_sequence,
            previous_signed_checkpoint_hash: payload.previous_signed_checkpoint_hash,
          }),
      covered_event_class: payload.covered_event_class,
      covered_event_type: payload.covered_event_type,
    },
    signer: {
      user_id: payload.signer_user_id,
      ...(params.variant === "user_identity" ? {} : { device_id: payload.signer_device_id }),
      signing_key_id: payload.signing_key_id,
    },
    authority_boundary: {
      scope_kind: payload.authorization_checkpoint_scope_kind,
      scope_id: payload.authorization_checkpoint_scope_id,
      checkpoint_protocol: "refmd.signed-key-directory-checkpoint",
      checkpoint_version: CURRENT_PROTOCOL_VERSION,
      checkpoint_hash_domain: "BLAKE3-256(JCS(payload))",
      checkpoint_sequence: payload.authorization_checkpoint_sequence,
      checkpoint_hash: payload.authorization_checkpoint_hash,
      required_authority: "audit_event_authorized_actor",
    },
  });
}

export function auditCheckpointHash(payload: StrictJsonValue): string {
  return blake3Base64Url(canonicalizeStrictBytes(payload));
}

export function assertAuditCheckpointPayload(
  variant: AuditCheckpointVariant,
  value: StrictJsonValue,
): Record<string, StrictJsonValue> {
  const payload = requiredRecord(value, "audit_checkpoint_payload_invalid");
  const deviceVariant = variant !== "user_identity";
  positiveInteger(payload.sequence, "audit_checkpoint_sequence_invalid");
  const genesis = isGenesisCheckpoint(payload);
  const expectedKeys = [
    "authorization_checkpoint_hash",
    "authorization_checkpoint_scope_id",
    "authorization_checkpoint_scope_kind",
    "authorization_checkpoint_sequence",
    "chain_scope_id",
    "chain_scope_kind",
    "covered_event_class",
    "covered_event_type",
    "event_hash",
    "protocol",
    "sequence",
    "signer_user_id",
    "signing_key_id",
    "version",
    ...(deviceVariant ? ["signer_device_id"] : []),
    ...(genesis ? [] : ["previous_signed_checkpoint_hash", "previous_signed_checkpoint_sequence"]),
  ].sort();
  if (Object.keys(payload).sort().join("\0") !== expectedKeys.join("\0")) {
    throw new Error("audit_checkpoint_payload_keys_invalid");
  }
  literal(payload.protocol, "refmd.signed-audit-checkpoint", "audit_checkpoint_protocol_invalid");
  literal(payload.version, CURRENT_PROTOCOL_VERSION, "audit_checkpoint_version_invalid");
  const scopeKind = requiredString(payload.chain_scope_kind, "audit_checkpoint_scope_invalid");
  if (
    (scopeKind === "user" && variant !== "user_identity" && variant !== "user_device") ||
    (scopeKind === "workspace" &&
      variant !== "workspace_device" &&
      variant !== "workspace_guest_device") ||
    (scopeKind !== "user" && scopeKind !== "workspace")
  ) {
    throw new Error("audit_checkpoint_scope_mismatch");
  }
  requiredString(payload.chain_scope_id, "audit_checkpoint_scope_invalid");
  literal(
    payload.authorization_checkpoint_scope_kind,
    payload.chain_scope_kind,
    "audit_checkpoint_scope_mismatch",
  );
  literal(
    payload.authorization_checkpoint_scope_id,
    payload.chain_scope_id,
    "audit_checkpoint_scope_mismatch",
  );
  requiredHash(payload.event_hash);
  requiredString(payload.signer_user_id, "audit_checkpoint_signer_invalid");
  if (deviceVariant) requiredString(payload.signer_device_id, "audit_checkpoint_signer_invalid");
  requiredHash(payload.signing_key_id);
  literal(payload.covered_event_class, "authority", "audit_checkpoint_class_invalid");
  requiredString(payload.covered_event_type, "audit_checkpoint_event_type_invalid");
  if (genesis) {
    literal(payload.authorization_checkpoint_sequence, 0, "audit_checkpoint_authority_invalid");
    literal(payload.authorization_checkpoint_hash, "GENESIS", "audit_checkpoint_authority_invalid");
  } else {
    positiveInteger(
      payload.previous_signed_checkpoint_sequence,
      "audit_checkpoint_previous_invalid",
    );
    requiredHash(payload.previous_signed_checkpoint_hash);
    positiveInteger(
      payload.authorization_checkpoint_sequence,
      "audit_checkpoint_authority_invalid",
    );
    requiredHash(payload.authorization_checkpoint_hash);
  }
  return payload;
}

function isGenesisCheckpoint(payload: Record<string, StrictJsonValue>): boolean {
  return (
    payload.authorization_checkpoint_sequence === 0 &&
    payload.authorization_checkpoint_hash === "GENESIS"
  );
}

function requiredRecord(value: StrictJsonValue, code: string): Record<string, StrictJsonValue> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(code);
  return value as Record<string, StrictJsonValue>;
}

function requiredString(value: StrictJsonValue | undefined, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function requiredHash(value: StrictJsonValue | undefined): string {
  const hash = requiredString(value, "audit_checkpoint_hash_invalid");
  if (!/^[A-Za-z0-9_-]{43}$/.test(hash)) throw new Error("audit_checkpoint_hash_invalid");
  return hash;
}

function positiveInteger(value: StrictJsonValue | undefined, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(code);
  }
  return value;
}

function literal(
  value: StrictJsonValue | undefined,
  expected: StrictJsonValue,
  code: string,
): void {
  if (value !== expected) throw new Error(code);
}
