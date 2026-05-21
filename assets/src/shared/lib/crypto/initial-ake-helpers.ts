import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";
import type { InitialAkePurpose } from "./initial-ake-types";

const DELIVERY_AAD_PROTOCOL = "refmd.initial-key-delivery-aad";
const INITIAL_AKE_REQUIRED_COMPONENTS = [
  "x25519-ephemeral",
  "mlkem768-ephemeral",
  "hkdf-sha256",
  "initiator-ake-commitment",
  "responder-prekey-signature",
] as const;
const textEncoder = new TextEncoder();

export function deriveAkeSecret(
  dh: Uint8Array,
  kem: Uint8Array,
  transcriptHash: Uint8Array,
  purpose: string,
): Uint8Array {
  return hkdf(
    sha256,
    concatBytes(dh, kem),
    transcriptHash,
    concatBytes(
      textEncoder.encode("RefMD Initial Hybrid Key Agreement v1"),
      textEncoder.encode(SUITE_IDS.INITIAL_AKE),
      textEncoder.encode(purpose),
    ),
    32,
  );
}

export function assertNonZeroSharedSecret(secret: Uint8Array): void {
  let acc = 0;
  for (const byte of secret) acc |= byte;
  if (acc === 0) throw new Error("x25519_shared_secret_invalid");
}

export function deriveDeliveryKey(
  secret: Uint8Array,
  transcriptHash: Uint8Array,
  contextHash: string,
  purpose: string,
): Uint8Array {
  return hkdf(
    sha256,
    secret,
    transcriptHash,
    concatBytes(
      textEncoder.encode("RefMD Initial Key Delivery v1"),
      textEncoder.encode(SUITE_IDS.INITIAL_AKE),
      textEncoder.encode(SUITE_IDS.INITIAL_DELIVERY),
      textEncoder.encode(purpose),
      textEncoder.encode(contextHash),
    ),
    32,
  );
}

export function initialDeliveryAad(params: {
  purpose: string;
  deliveryId: string;
  transcriptHash: string;
  contextHash: string;
  commitmentHash: string;
  senderHash: string;
  recipientHash: string;
  payloadMetadataHash: string;
}): Uint8Array {
  return canonicalizeStrictBytes({
    protocol: DELIVERY_AAD_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    purpose: params.purpose,
    delivery_id: params.deliveryId,
    initial_delivery_suite_id: SUITE_IDS.INITIAL_DELIVERY,
    initial_delivery_suite_rank: CURRENT_SUITE_RANK,
    ake_transcript_hash: params.transcriptHash,
    context_hash: params.contextHash,
    initiator_commitment_hash: params.commitmentHash,
    sender_hash: params.senderHash,
    recipient_hash: params.recipientHash,
    payload_metadata_hash: params.payloadMetadataHash,
    suite_id: SUITE_IDS.INITIAL_DELIVERY,
    suite_rank: CURRENT_SUITE_RANK,
  });
}

export function purposeContext(params: {
  purpose: InitialAkePurpose;
  userId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  workspaceId?: string;
  operationId: string;
  targetKeyKind: string;
  targetKeyVersion: number;
  challenge: string;
}): StrictJsonValue {
  if (params.purpose === "device_approval_kek_initial") {
    if (!params.workspaceId) throw new Error("workspace_id_required");
    return {
      purpose: params.purpose,
      owner_user_id: params.userId,
      workspace_id: params.workspaceId,
      registration_id: params.operationId,
      approved_device_id: params.recipientDeviceId,
      target_key_kind: params.targetKeyKind,
      target_key_version: params.targetKeyVersion,
      operation_id: params.operationId,
      challenge: params.challenge,
    };
  }
  if (params.purpose === "trust_transfer") {
    return {
      purpose: params.purpose,
      owner_user_id: params.userId,
      trust_transfer_id: params.operationId,
      source_device_id: params.senderDeviceId,
      target_device_id: params.recipientDeviceId,
      transfer_scope_hash: blake3Base64Url(
        canonicalizeStrictBytes({
          user_id: params.userId,
          source_device_id: params.senderDeviceId,
          target_device_id: params.recipientDeviceId,
        }),
      ),
      target_payload_kind: "trust_state_bundle",
      operation_id: params.operationId,
      challenge: params.challenge,
    };
  }
  return {
    purpose: params.purpose,
    owner_user_id: params.userId,
    distribution_id: params.operationId,
    recipient_device_id: params.recipientDeviceId,
    target_key_kind: params.targetKeyKind,
    target_key_version: params.targetKeyVersion,
    operation_id: params.operationId,
    challenge: params.challenge,
  };
}

export function purposeDirectory(params: {
  purpose: InitialAkePurpose;
  userCheckpointHash: string;
  userEventHeadHash: string;
  workspaceCheckpointHash: string;
  workspaceEventHeadHash: string;
  workspacePinsHash?: string;
}): StrictJsonValue {
  const policy = {
    suite_policy_version: 1,
    min_suite_rank: CURRENT_SUITE_RANK,
    allowed_suite_ids_hash: blake3Base64Url(
      canonicalizeStrictBytes({
        allowed_suite_ids: [
          SUITE_IDS.HYBRID_SIGNATURE,
          SUITE_IDS.INITIAL_AKE,
          SUITE_IDS.INITIAL_DELIVERY,
          SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
        ].sort(),
      }),
    ),
  };
  if (params.purpose === "device_approval_kek_initial") {
    return {
      user_checkpoint_hash: params.userCheckpointHash,
      workspace_checkpoint_hash: params.workspaceCheckpointHash,
      event_head_hash: params.workspaceEventHeadHash,
      ...policy,
    };
  }
  if (params.purpose === "trust_transfer") {
    if (!params.workspacePinsHash) throw new Error("workspace_pins_hash_required");
    return {
      user_checkpoint_hash: params.userCheckpointHash,
      user_event_head_hash: params.userEventHeadHash,
      workspace_pins_hash: params.workspacePinsHash,
      ...policy,
    };
  }
  return {
    user_checkpoint_hash: params.userCheckpointHash,
    user_event_head_hash: params.userEventHeadHash,
    ...policy,
  };
}

export function assertRecord(value: unknown, code: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

export function stringField(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

export function numberField(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) throw new Error(code);
  return value;
}

export function requiredComponentsValid(value: unknown): boolean {
  if (!Array.isArray(value) || value.length !== INITIAL_AKE_REQUIRED_COMPONENTS.length) {
    return false;
  }
  return INITIAL_AKE_REQUIRED_COMPONENTS.every((component, index) => value[index] === component);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
