import { getCryptoWorker } from "../worker/client";
import { getShareParticipantCryptoWorker } from "../worker/scoped";
import { blake3Base64Url } from "../hash";
import type { HybridSigningPublicKeyMaterial } from "../signature-types";
import type { HybridSignature } from "../signature";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import { CURRENT_PROTOCOL_VERSION, currentSuitePolicy } from "../suite";
import { assertKeyDirectoryEnvelope, type KeyDirectoryEnvelope } from "./types";

export function keyDirectoryEvent(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  sequence: number;
  eventType: string;
  actor: Record<string, unknown>;
  body: Record<string, unknown>;
  previousEventHash?: string;
}): Record<string, unknown> {
  return {
    protocol: "refmd.key-directory-event",
    version: CURRENT_PROTOCOL_VERSION,
    scope_kind: params.scopeKind,
    scope_id: params.scopeId,
    sequence: params.sequence,
    event_type: params.eventType,
    actor: params.actor,
    body: params.body,
    ...(params.previousEventHash ? { previous_event_hash: params.previousEventHash } : {}),
  };
}

export function keyDirectoryCheckpoint(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  sequence: number;
  issuedAt: string;
  coveredEventHead: Record<string, unknown>;
  identityKeys: Record<string, unknown>[];
  deviceKeys: Record<string, unknown>[];
  shareParticipantKeys: Record<string, unknown>[];
  revokedKeyIds: string[];
  previousCheckpointHash?: string;
}): Record<string, unknown> {
  const policy = currentSuitePolicy();
  return {
    protocol: "refmd.key-directory-checkpoint",
    version: CURRENT_PROTOCOL_VERSION,
    scope_kind: params.scopeKind,
    scope_id: params.scopeId,
    sequence: params.sequence,
    issued_at: params.issuedAt,
    suite_policy_version: policy.suite_policy_version,
    min_suite_rank: policy.min_suite_rank,
    allowed_suite_ids: policy.allowed_suite_ids,
    required_components: policy.required_components,
    identity_keys: params.identityKeys,
    device_keys: params.deviceKeys,
    share_participant_keys: params.shareParticipantKeys,
    revoked_key_ids: params.revokedKeyIds,
    covered_event_head: params.coveredEventHead,
    ...(params.previousCheckpointHash
      ? { previous_checkpoint_hash: params.previousCheckpointHash }
      : {}),
  };
}

export function keyDirectoryCheckpointHash(checkpointPayload: Record<string, unknown>): string {
  return blake3Base64Url(canonicalizeStrictBytes(checkpointPayload as StrictJsonValue));
}

export function actorWithCheckpointAuthority<T extends Record<string, unknown>>(
  actor: T,
  scopeKind: "user" | "workspace",
  scopeId: string,
  checkpointPayload: Record<string, unknown>,
): T & {
  key_scope_kind: "user" | "workspace";
  key_scope_id: string;
  key_checkpoint_sequence: number;
  key_checkpoint_hash: string;
} {
  return {
    ...actor,
    key_scope_kind: scopeKind,
    key_scope_id: scopeId,
    key_checkpoint_sequence: numberField(checkpointPayload.sequence),
    key_checkpoint_hash: keyDirectoryCheckpointHash(checkpointPayload),
  };
}

export function keyEntry(
  keyId: string,
  keyMaterial: unknown,
  validFrom: Record<string, unknown>,
): Record<string, unknown> {
  return {
    key_id: keyId,
    key_material: keyMaterial as StrictJsonValue,
    valid_from: validFrom,
  };
}

export function appendKeyEntryIfMissing(
  entries: Record<string, unknown>[],
  entry: Record<string, unknown>,
): Record<string, unknown>[] {
  return entries.some((candidate) => candidate.key_id === entry.key_id)
    ? entries
    : [...entries, entry];
}

export async function signEvent(
  ownerKind: "identity" | "device" | "share_participant_device",
  payload: Record<string, unknown>,
  shareSlug?: string,
  shareId?: string,
): Promise<KeyDirectoryEnvelope> {
  const worker =
    ownerKind === "share_participant_device"
      ? getShareParticipantCryptoWorker(stringField(shareSlug))
      : getCryptoWorker();
  const params = {
    eventType: payload.event_type as string,
    eventPayload: payload,
    ...(shareId ? { shareId } : {}),
  };
  const signed =
    ownerKind === "identity"
      ? await worker.signIdentityKeyDirectoryEvent(params)
      : ownerKind === "share_participant_device"
        ? await worker.signShareParticipantDeviceKeyDirectoryEvent(params)
        : await worker.signDeviceKeyDirectoryEvent(params);
  return assertKeyDirectoryEnvelope(
    { payload, signatures: [signatureEnvelope(signed)] },
    "key_directory_signed_event_invalid",
  );
}

export async function signCheckpoint(
  ownerKind: "identity" | "device" | "share_participant_device",
  variant:
    | "identity_initial"
    | "workspace_initial"
    | "identity_active"
    | "identity_rotation"
    | "workspace_authorized"
    | "invitation_redeem_authority"
    | "share_participant_document_operation"
    | "device_authorized",
  payload: Record<string, unknown>,
  shareSlug?: string,
  shareId?: string,
): Promise<KeyDirectoryEnvelope> {
  const worker =
    ownerKind === "share_participant_device"
      ? getShareParticipantCryptoWorker(stringField(shareSlug))
      : getCryptoWorker();
  const params = { variant, checkpointPayload: payload, ...(shareId ? { shareId } : {}) };
  const signed =
    ownerKind === "identity"
      ? await worker.signIdentityKeyDirectoryCheckpoint(params)
      : ownerKind === "share_participant_device"
        ? await worker.signShareParticipantDeviceKeyDirectoryCheckpoint(params)
        : await worker.signDeviceKeyDirectoryCheckpoint(params);
  return assertKeyDirectoryEnvelope(
    { payload, signatures: [signatureEnvelope(signed)] },
    "key_directory_signed_checkpoint_invalid",
  );
}

export function invitationRedeemSigner(input: {
  invitationId: string;
  signingKeyId: string;
}): Record<string, string> {
  return {
    signer_kind: "invitation_redeem_authority",
    invitation_id: input.invitationId,
    signing_key_id: input.signingKeyId,
  };
}

export function invitationRedeemActor(input: { invitationId: string; signingKeyId: string }) {
  return invitationRedeemSigner(input);
}

export async function signInvitationRedeemEvent(
  invitationId: string,
  payload: Record<string, unknown>,
): Promise<KeyDirectoryEnvelope> {
  const signed = await getCryptoWorker().signInvitationRedeemKeyDirectoryEvent({
    invitationId,
    eventType: payload.event_type as string,
    eventPayload: payload,
  });
  return assertKeyDirectoryEnvelope(
    { payload, signatures: [signatureEnvelope(signed)] },
    "key_directory_signed_invitation_event_invalid",
  );
}

export async function signInvitationRedeemCheckpoint(
  invitationId: string,
  payload: Record<string, unknown>,
): Promise<KeyDirectoryEnvelope> {
  const signed = await getCryptoWorker().signInvitationRedeemKeyDirectoryCheckpoint({
    invitationId,
    checkpointPayload: payload,
  });
  return assertKeyDirectoryEnvelope(
    { payload, signatures: [signatureEnvelope(signed)] },
    "key_directory_signed_invitation_checkpoint_invalid",
  );
}

export function activeIdentitySigningKeyId(
  checkpointPayload: Record<string, unknown>,
  userId: string,
): string {
  const entry = keyEntries(checkpointPayload, "identity_keys").find(
    (candidate) =>
      !("revoked_at" in candidate) &&
      isSigningMaterial(candidate.key_material) &&
      candidate.key_material.owner_kind === "identity" &&
      candidate.key_material.owner_id === userId,
  );
  if (!entry) throw new Error("key_directory_identity_signing_key_missing");
  return stringField(entry.key_id);
}

export function activeDeviceSigningKeyId(
  checkpointPayload: Record<string, unknown>,
  deviceId: string,
): string {
  const entry = keyEntries(checkpointPayload, "device_keys").find(
    (candidate) =>
      !("revoked_at" in candidate) &&
      isSigningMaterial(candidate.key_material) &&
      candidate.key_material.owner_kind === "device" &&
      candidate.key_material.owner_id === deviceId,
  );
  if (!entry) throw new Error("key_directory_device_signing_key_missing");
  return stringField(entry.key_id);
}

export function nextWorkspaceSequence(checkpointEnvelope: Record<string, unknown>): number {
  const checkpointPayload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");
  return numberField(coveredHead.head_sequence) + 1;
}

export function keyEntries(
  checkpointPayload: Record<string, unknown>,
  key: string,
): Record<string, unknown>[] {
  const value = checkpointPayload[key];
  if (!Array.isArray(value)) return [];
  return value.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === "object" && entry !== null && !Array.isArray(entry),
  );
}

export function checkpointShareParticipantKeys(
  checkpointPayload: Record<string, unknown>,
): Record<string, unknown>[] {
  return keyEntries(checkpointPayload, "share_participant_keys");
}

export function revokeKeyEntry(
  entries: Record<string, unknown>[],
  keyId: string,
  revokedAt: Record<string, unknown>,
): Record<string, unknown>[] {
  let found = false;
  const updated = entries.map((entry) => {
    if (entry.key_id !== keyId) return entry;
    if ("revoked_at" in entry) throw new Error("key_directory_key_already_revoked");
    found = true;
    return { ...entry, revoked_at: revokedAt };
  });
  if (!found) return entries;
  return updated;
}

export function checkpointHasKey(
  checkpointPayload: Record<string, unknown>,
  keyId: string,
): boolean {
  return keyEntries(checkpointPayload, "identity_keys")
    .concat(keyEntries(checkpointPayload, "device_keys"))
    .some((entry) => entry.key_id === keyId && !("revoked_at" in entry));
}

export function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

export function eventRefForKey(
  events: Record<string, unknown>[],
  keyId: string,
): Record<string, unknown> {
  const event = events.find((candidate) => {
    const body = candidate.body as Record<string, unknown> | undefined;
    return body?.key_id === keyId;
  });
  if (!event) throw new Error("key_directory_revocation_event_missing");
  return eventRef("workspace", stringField(event.scope_id), event);
}

export function isSigningMaterial(value: unknown): value is HybridSigningPublicKeyMaterial {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    (value as Record<string, unknown>).protocol === "refmd.hybrid-signing-key-material"
  );
}

export function numberField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error("key_directory_number_invalid");
  }
  return value;
}

export function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("key_directory_string_invalid");
  }
  return value;
}

export function base64UrlRandom(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

export function signatureEnvelope(signed: {
  signer: Record<string, string>;
  signature: HybridSignature;
}): KeyDirectoryEnvelope["signatures"][number] {
  return {
    signer: signed.signer as unknown as KeyDirectoryEnvelope["signatures"][number]["signer"],
    signature: signed.signature,
  };
}

export function identityActor(userId: string, signingKeyId: string): Record<string, string> {
  return { signer_kind: "identity", user_id: userId, signing_key_id: signingKeyId };
}

export function deviceActor(
  userId: string,
  deviceId: string,
  signingKeyId: string,
): Record<string, string> {
  return {
    signer_kind: "device",
    user_id: userId,
    device_id: deviceId,
    signing_key_id: signingKeyId,
  };
}

export function shareParticipantDeviceActor(
  shareId: string,
  principalId: string,
  deviceId: string,
  signingKeyId: string,
): Record<string, string> {
  return {
    signer_kind: "share_participant_device",
    share_id: shareId,
    share_participant_principal_id: principalId,
    share_participant_device_id: deviceId,
    signing_key_id: signingKeyId,
  };
}

export function eventHash(event: Record<string, unknown>): string {
  return blake3Base64Url(canonicalizeStrictBytes(event as StrictJsonValue));
}

export function eventRef(
  scopeKind: "user" | "workspace",
  scopeId: string,
  event: Record<string, unknown>,
): Record<string, unknown> {
  return {
    scope_kind: scopeKind,
    scope_id: scopeId,
    event_sequence: event.sequence,
    event_hash: eventHash(event),
  };
}

export function eventHead(event: Record<string, unknown>): Record<string, unknown> {
  return {
    head_sequence: event.sequence,
    head_hash: eventHash(event),
  };
}
