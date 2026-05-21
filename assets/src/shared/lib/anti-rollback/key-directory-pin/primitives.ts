import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
import type {
  HybridSignature,
  HybridSigningPublicKeyMaterial,
} from "@/shared/lib/crypto/signature-types";
import type { SigningOwnerKind } from "@/shared/lib/crypto/signature-transcript-core";

import type { SignedKeyDirectoryEnvelope } from "./types";

export function stableJsonForComparison(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJsonForComparison(item) ?? "null").join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .flatMap((key) => {
        const encoded = stableJsonForComparison(value[key]);
        return encoded === undefined ? [] : [`${JSON.stringify(key)}:${encoded}`];
      })
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sameCheckpointStateEntries(left: unknown, right: unknown): boolean {
  return (
    normalizedCheckpointStateEntries(left).join("\n") ===
    normalizedCheckpointStateEntries(right).join("\n")
  );
}

export function normalizedCheckpointStateEntries(value: unknown): string[] {
  const seen = new Set<string>();
  return arrayField(value)
    .map((entry) => {
      let entryId: string;
      let canonical: string;
      if (isRecord(entry)) {
        entryId = stringField(entry.key_id, "checkpoint_state_entry_key_id_invalid");
        canonical =
          stableJsonForComparison(entry) ??
          (() => {
            throw new Error("checkpoint_state_entry_invalid");
          })();
      } else if (typeof entry === "string") {
        entryId = entry;
        canonical = JSON.stringify(entry);
      } else {
        throw new Error("checkpoint_state_entry_invalid");
      }
      if (seen.has(entryId)) throw new Error("checkpoint_state_entry_duplicate");
      seen.add(entryId);
      return `${entryId}:${canonical}`;
    })
    .sort();
}

export function shareParticipantSignerKeyId(event: SignedKeyDirectoryEnvelope): string | null {
  const signer = event.signatures.find(
    (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "share_participant_device",
  )?.signer;
  if (!signer) return null;
  return stringField(signer.signing_key_id, "signing_key_id_invalid");
}

export function shareParticipantSignerDeviceId(event: SignedKeyDirectoryEnvelope): string {
  const signer = event.signatures.find(
    (signatureEnvelope) => signatureEnvelope.signer.signer_kind === "share_participant_device",
  )?.signer;
  if (!signer) throw new Error("share_participant_signer_missing");
  return stringField(signer.share_participant_device_id, "share_participant_device_id_invalid");
}

export function assertCheckpointStateMatchesReplay(
  candidatePayload: Record<string, unknown>,
  replayPayload: Record<string, unknown>,
): void {
  for (const key of ["identity_keys", "device_keys", "share_participant_keys", "revoked_key_ids"]) {
    if (!sameCheckpointStateEntries(candidatePayload[key], replayPayload[key])) {
      throw new Error("checkpoint_state_replay_mismatch");
    }
  }
}

export function updateKeyEntries(
  checkpointPayload: Record<string, unknown>,
  key: "identity_keys" | "device_keys" | "share_participant_keys",
  keyEntry: unknown,
): Record<string, unknown> {
  if (!isRecord(keyEntry)) throw new Error("key_directory_key_entry_missing");
  const entries = arrayField(checkpointPayload[key]);
  if (entries.some((entry) => isRecord(entry) && entry.key_id === keyEntry.key_id)) {
    throw new Error("key_directory_key_entry_duplicate");
  }
  return { ...checkpointPayload, [key]: [...entries, keyEntry] };
}

export function updateKeyEntriesIfMissing(
  checkpointPayload: Record<string, unknown>,
  key: "identity_keys" | "device_keys" | "share_participant_keys",
  keyEntry: unknown,
): Record<string, unknown> {
  if (!isRecord(keyEntry)) throw new Error("key_directory_key_entry_missing");
  const entries = arrayField(checkpointPayload[key]);
  if (entries.some((entry) => isRecord(entry) && entry.key_id === keyEntry.key_id)) {
    return checkpointPayload;
  }
  return { ...checkpointPayload, [key]: [...entries, keyEntry] };
}

export function revokeKeyEntry(
  checkpointPayload: Record<string, unknown>,
  keyId: string,
  event: SignedKeyDirectoryEnvelope,
): Record<string, unknown> {
  const eventRef = eventRefFor(event);
  let found = false;
  const update = (entries: unknown[]) =>
    entries.map((entry) => {
      if (!isRecord(entry) || entry.key_id !== keyId) return entry;
      found = true;
      if ("revoked_at" in entry) throw new Error("key_directory_key_already_revoked");
      return { ...entry, revoked_at: eventRef };
    });
  const next = {
    ...checkpointPayload,
    identity_keys: update(arrayField(checkpointPayload.identity_keys)),
    device_keys: update(arrayField(checkpointPayload.device_keys)),
    share_participant_keys: update(arrayField(checkpointPayload.share_participant_keys)),
    revoked_key_ids: [...new Set([...arrayField(checkpointPayload.revoked_key_ids), keyId])],
  };
  if (!found) throw new Error("key_directory_key_entry_missing");
  return next;
}

export function assertKeyEntryValidFromEvent(
  entry: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
): void {
  if (!keyEntryValidFromEvent(entry, event)) {
    throw new Error("key_entry_valid_from_mismatch");
  }
}

export function keyEntryValidFromEvent(
  entry: Record<string, unknown>,
  event: SignedKeyDirectoryEnvelope,
): boolean {
  const expected = eventRefFor(event);
  return (
    isRecord(entry.valid_from) &&
    entry.valid_from.scope_kind === expected.scope_kind &&
    entry.valid_from.scope_id === expected.scope_id &&
    entry.valid_from.event_sequence === expected.event_sequence &&
    entry.valid_from.event_hash === expected.event_hash
  );
}

export function eventRefFor(event: SignedKeyDirectoryEnvelope): Record<string, unknown> {
  return {
    scope_kind: event.payload.scope_kind,
    scope_id: event.payload.scope_id,
    event_sequence: event.payload.sequence,
    event_hash: eventHash(event),
  };
}

export function checkpointSignatureVariant(
  payload: Record<string, unknown>,
  signer: Record<string, unknown>,
  previousPayload?: Record<string, unknown>,
):
  | "identity_initial"
  | "workspace_initial"
  | "identity_active"
  | "identity_rotation"
  | "workspace_authorized"
  | "invitation_redeem_authority"
  | "share_participant_document_operation"
  | "device_authorized" {
  if (
    payload.scope_kind === "user" &&
    payload.sequence === 1 &&
    signer.signer_kind === "identity"
  ) {
    return "identity_initial";
  }
  if (payload.scope_kind === "user" && signer.signer_kind === "identity") {
    return identityRotationCheckpoint(payload) ? "identity_rotation" : "identity_active";
  }
  if (
    payload.scope_kind === "workspace" &&
    payload.sequence === 1 &&
    signer.signer_kind === "device"
  ) {
    return "workspace_initial";
  }
  if (payload.scope_kind === "workspace" && signer.signer_kind === "device") {
    return deviceAuthorizedCheckpointSigner(previousPayload, payload, signer)
      ? "device_authorized"
      : "workspace_authorized";
  }
  if (payload.scope_kind === "workspace" && signer.signer_kind === "share_participant_device") {
    return "share_participant_document_operation";
  }
  if (payload.scope_kind === "workspace" && signer.signer_kind === "invitation_redeem_authority") {
    return "invitation_redeem_authority";
  }
  throw new Error("checkpoint_signer_kind_invalid");
}

function deviceAuthorizedCheckpointSigner(
  previousPayload: Record<string, unknown> | undefined,
  checkpointPayload: Record<string, unknown>,
  signer: Record<string, unknown>,
): boolean {
  if (!previousPayload || checkpointPayload.scope_kind !== "workspace") return false;
  if (signer.signer_kind !== "device" || typeof signer.signing_key_id !== "string") return false;
  return (
    !keyEntryPresent(previousPayload.device_keys, signer.signing_key_id) &&
    keyEntryPresent(checkpointPayload.device_keys, signer.signing_key_id)
  );
}

function keyEntryPresent(entries: unknown, keyId: string): boolean {
  if (!Array.isArray(entries)) return false;
  return entries.some(
    (entry) => isRecord(entry) && entry.key_id === keyId && !("revoked_at" in entry),
  );
}

function identityRotationCheckpoint(payload: Record<string, unknown>): boolean {
  if (payload.sequence === 1) return false;
  const entries = payload.identity_keys;
  if (!Array.isArray(entries)) return false;
  return (
    entries.filter(
      (entry) =>
        isRecord(entry) &&
        isRecord(entry.key_material) &&
        entry.key_material.owner_kind === "identity" &&
        entry.key_material.protocol === "refmd.hybrid-signing-key-material" &&
        !Object.prototype.hasOwnProperty.call(entry, "revoked_at"),
    ).length >= 2
  );
}

export function isRequiredCheckpointSigner(
  payload: Record<string, unknown>,
  signer: Record<string, unknown>,
): boolean {
  return (
    (payload.scope_kind === "user" && signer.signer_kind === "identity") ||
    (payload.scope_kind === "workspace" &&
      (signer.signer_kind === "device" ||
        signer.signer_kind === "share_participant_device" ||
        signer.signer_kind === "invitation_redeem_authority"))
  );
}

export function signingKeyMaterialById(
  checkpointPayload: Record<string, unknown>,
): Map<string, HybridSigningPublicKeyMaterial> {
  const materials = [
    ...arrayField(checkpointPayload.identity_keys),
    ...arrayField(checkpointPayload.device_keys),
    ...arrayField(checkpointPayload.share_participant_keys),
    ...arrayField(checkpointPayload.temporary_authority_keys),
  ];
  const result = new Map<string, HybridSigningPublicKeyMaterial>();
  for (const entry of materials) {
    if (!isRecord(entry)) continue;
    const material = entry.key_material;
    if (isSigningMaterial(material)) {
      result.set(stringField(entry.key_id, "key_id_invalid"), material);
    }
  }
  return result;
}

export function keyEntryById(
  checkpointPayload: Record<string, unknown>,
  keyId: string,
): Record<string, unknown> {
  const entry = findKeyEntryById(checkpointPayload, keyId);
  if (entry) return entry;
  throw new Error("key_directory_key_entry_missing");
}

export function findKeyEntryById(
  checkpointPayload: Record<string, unknown>,
  keyId: string,
): Record<string, unknown> | null {
  for (const entry of [
    ...arrayField(checkpointPayload.identity_keys),
    ...arrayField(checkpointPayload.device_keys),
    ...arrayField(checkpointPayload.share_participant_keys),
    ...arrayField(checkpointPayload.temporary_authority_keys),
  ]) {
    if (isRecord(entry) && entry.key_id === keyId) return entry;
  }
  return null;
}

export function assertKeyEntryActiveAtSequence(
  checkpointPayload: Record<string, unknown>,
  keyId: string,
  sequence: number,
): void {
  const entry = keyEntryById(checkpointPayload, keyId);
  const validFrom = entry.valid_from as Record<string, unknown> | undefined;
  if (!validFrom) throw new Error("key_valid_from_invalid");
  if (numberField(validFrom.event_sequence, "event_sequence_invalid") > sequence) {
    throw new Error("key_directory_signer_not_yet_valid");
  }
  if (isRecord(entry.revoked_at)) {
    if (numberField(entry.revoked_at.event_sequence, "event_sequence_invalid") <= sequence) {
      throw new Error("key_directory_signer_revoked");
    }
  }
}

export function assertSignerMatchesMaterial(
  signer: Record<string, unknown>,
  material: HybridSigningPublicKeyMaterial,
): void {
  const signerKind = stringField(signer.signer_kind, "signer_kind_invalid");
  const expectedOwnerKind: SigningOwnerKind =
    signerKind === "identity"
      ? "identity"
      : signerKind === "device"
        ? "device"
        : signerKind === "share_participant_device"
          ? "share_participant_device"
          : signerKind === "invitation_redeem_authority"
            ? "invitation_redeem_authority"
            : (() => {
                throw new Error("signer_kind_invalid");
              })();
  if (material.owner_kind !== expectedOwnerKind) throw new Error("signer_owner_kind_mismatch");
  const expectedOwnerId =
    signerKind === "identity"
      ? signer.user_id
      : signerKind === "invitation_redeem_authority"
        ? signer.invitation_id
        : signerKind === "share_participant_device"
          ? signer.share_participant_device_id
          : signer.device_id;
  if (material.owner_id !== expectedOwnerId) throw new Error("signer_owner_id_mismatch");
  if (computeSigningKeyId(material) !== signer.signing_key_id) {
    throw new Error("signer_key_id_mismatch");
  }
}

export function assertActorMatchesSigner(
  actor: Record<string, unknown> | undefined,
  signer: Record<string, unknown>,
): void {
  if (!actor) throw new Error("event_actor_signer_mismatch");
  for (const key of [
    "signer_kind",
    "share_id",
    "share_participant_principal_id",
    "share_participant_device_id",
    "user_id",
    "principal_id",
    "device_id",
    "invitation_id",
    "signing_key_id",
  ]) {
    if ((key in actor || key in signer) && actor[key] !== signer[key]) {
      throw new Error("event_actor_signer_mismatch");
    }
  }
}

export function shareParticipantKeyEntryById(
  checkpointPayload: Record<string, unknown>,
  keyId: string,
): Record<string, unknown> {
  for (const entry of arrayField(checkpointPayload.share_participant_keys)) {
    if (isRecord(entry) && entry.key_id === keyId) return entry;
  }
  throw new Error("share_participant_key_entry_missing");
}

export function assertOwner(
  material: unknown,
  ownerKind: SigningOwnerKind | "identity",
  ownerId: string,
): void {
  if (!isRecord(material)) throw new Error("key_material_invalid");
  if (material.owner_kind !== ownerKind || material.owner_id !== ownerId) {
    throw new Error("key_material_owner_mismatch");
  }
}

export function checkpointHash(envelope: SignedKeyDirectoryEnvelope): string {
  return blake3Base64Url(canonicalizeStrictBytes(envelope.payload as StrictJsonValue));
}

export function hashKeyDirectoryCheckpointEnvelope(envelope: Record<string, unknown>): string {
  return checkpointHash(assertEnvelope(envelope));
}

export function eventHash(envelope: SignedKeyDirectoryEnvelope): string {
  return blake3Base64Url(canonicalizeStrictBytes(envelope.payload as StrictJsonValue));
}

export function assertEnvelope(envelope: Record<string, unknown>): SignedKeyDirectoryEnvelope {
  if (
    !isRecord(envelope.payload) ||
    !Array.isArray(envelope.signatures) ||
    envelope.signatures.length === 0
  ) {
    throw new Error("key_directory_envelope_invalid");
  }
  return {
    payload: envelope.payload,
    signatures: envelope.signatures.map((signatureEnvelope) => {
      if (
        !isRecord(signatureEnvelope) ||
        !isRecord(signatureEnvelope.signer) ||
        !isRecord(signatureEnvelope.signature)
      ) {
        throw new Error("key_directory_signature_envelope_invalid");
      }
      return {
        signer: signatureEnvelope.signer,
        signature: signatureEnvelope.signature as unknown as HybridSignature,
      };
    }),
  };
}

export function arrayField(value: unknown): unknown[] {
  if (!Array.isArray(value)) return [];
  return value;
}

export function isSigningMaterial(value: unknown): value is HybridSigningPublicKeyMaterial {
  return (
    isRecord(value) &&
    value.protocol === "refmd.hybrid-signing-key-material" &&
    value.version === 1 &&
    typeof value.owner_kind === "string" &&
    typeof value.owner_id === "string" &&
    typeof value.ed25519_public === "string" &&
    typeof value.mldsa65_public === "string"
  );
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function numberField(value: unknown, error: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error(error);
  }
  return value;
}

export function stringField(value: unknown, error: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(error);
  }
  return value;
}
