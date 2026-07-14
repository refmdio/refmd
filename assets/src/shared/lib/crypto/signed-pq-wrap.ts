import {
  assertHybridEncryptionPrivateKeyMaterial,
  assertHybridEncryptionPublicKeyMaterial,
  computeHybridEncryptionKeyId,
  publicHybridEncryptionMaterialFromPrivate,
  type HybridEncryptionPrivateKeyMaterial,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import {
  buildPqWrapTranscript,
  computeSigningKeyId,
  publicKeyMaterialFromPrivate,
  signPqWrapSignature,
  verifyPqWrapSignature,
  type HybridSignature,
  type HybridSigningPrivateKeyMaterial,
  type HybridSigningPublicKeyMaterial,
} from "./signature";
import type { VerifiedSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";
import { decodeBase64UrlStrict, encodeBase64Url } from "./encoding";
import {
  discardNativeHpkeSender,
  nativeHpkeOpen,
  nativeHpkeSeal,
  nativeHpkeSetupSender,
} from "./worker/native-hpke";

const WRAP_PROTOCOL = "refmd.signed-pq-hybrid-wrap";
const KEM_ID = 0x647a;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0003;
const VERIFIED_OPERATION_PROTOCOL = "refmd.verified-signed-pq-wrap-operation";
const VERIFIED_OPERATION_VERSION = 1;
const MLKEM_CIPHERTEXT_BYTES = 1088;
const X25519_PUBLIC_BYTES = 32;
const ENCAPSULATED_BYTES = MLKEM_CIPHERTEXT_BYTES + X25519_PUBLIC_BYTES;

export type SignedPqWrapPurpose =
  | "workspace_device_kek_wrap"
  | "workspace_member_kek_wrap"
  | "share_participant_bootstrap_wrap"
  | "share_link_secret_backup_wrap"
  | "workspace_invitation_kek_wrap"
  | "guest_invitation_workspace_kek_wrap"
  | "guest_invitation_share_key_wrap";

type SignedPqWrapEventScope = {
  scope_kind: "user" | "workspace" | "document" | "folder";
  scope_id: string;
};
type SignedPqWrapSender = {
  signer_kind: "device";
  user_id: string;
  device_id: string;
  signing_key_id: string;
  key_scope_kind: SignedPqWrapEventScope["scope_kind"];
  key_scope_id: string;
  key_checkpoint_sequence: number;
  key_checkpoint_hash: string;
};
type SignedPqWrapRecipient = {
  encryption_key_id: string;
  key_scope_kind: SignedPqWrapEventScope["scope_kind"];
  key_scope_id: string;
  key_checkpoint_sequence: number;
  key_checkpoint_hash: string;
} & (
  | { recipient_kind: "device"; user_id: string; device_id: string }
  | { recipient_kind: "user_identity"; user_id: string }
  | { recipient_kind: "invitee"; invitee_user_id: string; invitee_device_id: string }
  | { recipient_kind: "guest"; guest_user_id: string; guest_device_id: string }
  | {
      recipient_kind: "share_participant_device";
      share_participant_principal_id: string;
      share_participant_device_id: string;
    }
);
type WorkspaceDeviceKekWrapResource = {
  workspace_id: string;
  target_user_id: string;
  target_device_id: string;
  kek_version: number;
};
type WorkspaceMemberKekWrapResource = {
  workspace_id: string;
  target_user_id: string;
  kek_version: number;
};
type ShareParticipantBootstrapWrapResource = {
  workspace_id: string;
  share_id: string;
  share_participant_principal_id: string;
  share_participant_device_id: string;
  scope_kind: "document" | "folder";
  scope_id: string;
  permission: "view" | "edit";
  document_scope_hash: string;
  share_session_id: string;
  share_key_version: number;
  dek_version: number;
  bootstrap_version: number;
};
type ShareLinkSecretBackupWrapResource = {
  workspace_id: string;
  share_id: string;
  token_hash: string;
  scope_kind: "document" | "folder";
  scope_id: string;
  permission: "view" | "edit";
  password_protected: boolean;
  created_event_hash: string;
  share_capability_secret_commitment: string;
  password_capability_secret_commitment: string;
  workspace_pin_bootstrap_hash: string;
  recipient_user_id: string;
  recipient_device_id: string;
  recipient_encryption_key_id: string;
  key_checkpoint_hash: string;
};
type WorkspaceInvitationKekWrapResource = {
  workspace_id: string;
  invitation_id: string;
  redeemed_user_id: string;
  redeemed_device_id: string;
  recipient_encryption_key_id: string;
  role_id: string;
  kek_version: number;
  workspace_invitation_redeemed_event_hash: string;
};
type GuestInvitationWorkspaceKekWrapResource = {
  workspace_id: string;
  guest_invitation_id: string;
  guest_user_id: string;
  guest_device_id: string;
  recipient_encryption_key_id: string;
  guest_grant_id: string;
  scope_kind: "workspace";
  scope_id: "none";
  permission: "view" | "edit";
  kek_version: number;
  guest_invitation_redeemed_event_hash: string;
};
type GuestInvitationShareKeyWrapResource = {
  workspace_id: string;
  guest_invitation_id: string;
  guest_user_id: string;
  guest_device_id: string;
  recipient_encryption_key_id: string;
  share_id: string;
  scope_kind: "document" | "folder";
  scope_id: string;
  permission: "view" | "edit";
  document_scope_hash: string;
  share_key_version: number;
  dek_version: number;
  guest_invitation_redeemed_event_hash: string;
};
type SignedPqWrapResource =
  | WorkspaceDeviceKekWrapResource
  | WorkspaceMemberKekWrapResource
  | ShareParticipantBootstrapWrapResource
  | ShareLinkSecretBackupWrapResource
  | WorkspaceInvitationKekWrapResource
  | GuestInvitationWorkspaceKekWrapResource
  | GuestInvitationShareKeyWrapResource;

export interface SignedPqWrapRecord {
  protocol: typeof WRAP_PROTOCOL;
  protocol_version: typeof CURRENT_PROTOCOL_VERSION;
  suite_id: typeof SUITE_IDS.SIGNED_PQ_HYBRID_WRAP;
  suite_rank: typeof CURRENT_SUITE_RANK;
  purpose: SignedPqWrapPurpose;
  resource: SignedPqWrapResource;
  sender: SignedPqWrapSender;
  recipient: SignedPqWrapRecipient;
  event_scope: SignedPqWrapEventScope;
  event: {
    wrap_event_sequence: number;
    wrap_event_hash: string;
    wrap_event_body_hash: string;
  };
  operation_checkpoint: {
    checkpoint_sequence: number;
    checkpoint_hash: string;
    covered_event_head_sequence: number;
    covered_event_head_hash: string;
  };
  hpke: {
    mode: "base";
    kem_id: typeof KEM_ID;
    kdf_id: typeof KDF_ID;
    aead_id: typeof AEAD_ID;
    enc: string;
    ciphertext: string;
  };
  transcript_hash: string;
  signature: HybridSignature;
}

export interface CreateSignedPqWrapParams {
  purpose: SignedPqWrapPurpose;
  plaintext: Uint8Array;
  recipientPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  senderSigningPrivateKeyMaterial: HybridSigningPrivateKeyMaterial;
  senderUserId: string;
  senderDeviceId: string;
  resource: StrictJsonValue;
  eventScope: SignedPqWrapEventScope;
  operationCheckpoint: {
    sequence: number;
    checkpointHash: string;
    coveredHeadSequence: number;
    coveredHeadHash: string;
  };
  eventPrevious?: {
    sequence: number;
    hash: string;
  };
  recipientKeyCheckpoint?: {
    scopeKind: "user" | "workspace" | "document" | "folder";
    scopeId: string;
    sequence: number;
    checkpointHash: string;
  };
}

export interface OpenSignedPqWrapParams {
  record: SignedPqWrapRecord;
  recipientPrivateKeyMaterial: HybridEncryptionPrivateKeyMaterial;
  senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  verifiedOperation: VerifiedSignedPqWrapOperation;
}

const SIGNED_PQ_WRAP_WIRE_FIELDS = [
  "protocol",
  "protocol_version",
  "suite_id",
  "suite_rank",
  "purpose",
  "resource",
  "sender",
  "recipient",
  "event_scope",
  "event",
  "operation_checkpoint",
  "hpke",
  "transcript_hash",
  "signature",
] as const;

const SIGNED_PQ_WRAP_CONTAINER_FIELDS = [
  "device_id",
  "is_active",
  "key_version",
  "sender_approval_delivery_artifacts",
  "sender_approval_delivery_commitments",
  "sender_device_id",
  "sender_client_nonce",
  "sender_hybrid_encryption_public_key_material",
  "sender_hybrid_signing_public_key_material",
  "sender_identity_hybrid_encryption_public_key_material",
  "sender_approval_signature",
  "sender_identity_hybrid_signing_public_key_material",
  "sender_approval_proof",
  "sender_approval_signature_surface",
  "sender_user_id",
  "target_device_id",
  "target_user_id",
  "workspace_id",
  "workspace_key_directory_checkpoint",
  "workspace_key_directory_checkpoint_ancestry",
  "workspace_key_directory_event_ancestry",
  "workspace_key_directory_events",
] as const;

export function signedPqWrapRecordFromEnvelope(value: unknown): SignedPqWrapRecord {
  const envelope = asUnknownRecord(value, "signed_pq_wrap_envelope_invalid");
  assertAllowedKeys(envelope, [...SIGNED_PQ_WRAP_WIRE_FIELDS, ...SIGNED_PQ_WRAP_CONTAINER_FIELDS]);
  const record = Object.fromEntries(
    SIGNED_PQ_WRAP_WIRE_FIELDS.map((field) => {
      if (!(field in envelope)) throw new Error("signed_pq_wrap_field_missing");
      return [field, envelope[field]];
    }),
  ) as unknown as SignedPqWrapRecord;
  assertSignedPqWrapRecord(record);
  return record;
}

export function createSignedPqWrap(params: CreateSignedPqWrapParams): SignedPqWrapRecord {
  const resource = params.resource;
  assertResourceSchema(params.purpose, resource);
  assertHybridEncryptionPublicKeyMaterial(params.recipientPublicKeyMaterial);
  const senderPublic = publicKeyMaterialFromPrivate(params.senderSigningPrivateKeyMaterial);
  const senderSigningKeyId = computeSigningKeyId(senderPublic);
  const recipientKeyId = computeHybridEncryptionKeyId(params.recipientPublicKeyMaterial);
  const recipientKeyCheckpoint = params.recipientKeyCheckpoint ?? {
    scopeKind: params.eventScope.scope_kind,
    scopeId: params.eventScope.scope_id,
    sequence: params.operationCheckpoint.sequence,
    checkpointHash: params.operationCheckpoint.checkpointHash,
  };
  const base = unsignedRecordBase({
    purpose: params.purpose,
    resource,
    sender: {
      signer_kind: "device",
      user_id: params.senderUserId,
      device_id: params.senderDeviceId,
      signing_key_id: senderSigningKeyId,
      key_scope_kind: params.eventScope.scope_kind,
      key_scope_id: params.eventScope.scope_id,
      key_checkpoint_sequence: params.operationCheckpoint.sequence,
      key_checkpoint_hash: params.operationCheckpoint.checkpointHash,
    },
    recipient: recipientForResource({
      purpose: params.purpose,
      resource,
      encryption_key_id: recipientKeyId,
      key_scope_kind: recipientKeyCheckpoint.scopeKind,
      key_scope_id: recipientKeyCheckpoint.scopeId,
      owner_kind: params.recipientPublicKeyMaterial.owner_kind,
      owner_id: params.recipientPublicKeyMaterial.owner_id,
      key_checkpoint_sequence: recipientKeyCheckpoint.sequence,
      key_checkpoint_hash: recipientKeyCheckpoint.checkpointHash,
    }),
    eventScope: params.eventScope,
    operationCheckpoint: params.operationCheckpoint,
  });
  const info = hpkeInfo(base);
  const sender = nativeHpkeSetupSender({
    publicKey: decodeBase64UrlStrict(params.recipientPublicKeyMaterial.hybrid_public, 1216),
    info,
  });
  let senderConsumed = false;
  let hpkeEnc: Uint8Array;
  let aad: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    hpkeEnc = sender.enc;
    aad = wrapAad(base, hpkeEnc);
    ciphertext = nativeHpkeSeal({
      contextHandle: sender.contextHandle,
      aad,
      plaintext: params.plaintext,
    });
    senderConsumed = true;
  } finally {
    if (!senderConsumed) discardNativeHpkeSender(sender.contextHandle);
  }
  const wrapBody = wrapBodyForHash(base, hpkeEnc, ciphertext);
  const wrapBodyHash = blake3Base64Url(canonicalizeStrictBytes(wrapBody));
  const wrapEventBody = {
    purpose: params.purpose,
    recipient: base.recipient,
    resource,
    resource_hash: blake3Base64Url(canonicalizeStrictBytes(resource)),
    sender: base.sender,
    wrap_body_hash: wrapBodyHash,
    wrap_protocol: WRAP_PROTOCOL,
    wrap_suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    wrap_suite_rank: CURRENT_SUITE_RANK,
    wrap_version: CURRENT_PROTOCOL_VERSION,
  };
  const wrapEventBodyHash = blake3Base64Url(canonicalizeStrictBytes(wrapEventBody));
  const eventPrevious = params.eventPrevious ?? {
    sequence: params.operationCheckpoint.coveredHeadSequence,
    hash: params.operationCheckpoint.coveredHeadHash,
  };
  if (!Number.isInteger(eventPrevious.sequence) || eventPrevious.sequence < 0) {
    throw new Error("signed_pq_wrap_event_previous_invalid");
  }
  const wrapEventSequence = eventPrevious.sequence + 1;
  const wrapEvent = {
    protocol: "refmd.key-directory-event",
    version: CURRENT_PROTOCOL_VERSION,
    scope_kind: (params.eventScope as Record<string, unknown>).scope_kind,
    scope_id: (params.eventScope as Record<string, unknown>).scope_id,
    sequence: wrapEventSequence,
    event_type: "wrap_issued",
    actor: base.sender,
    previous_event_hash: eventPrevious.hash,
    body: wrapEventBody,
  } as StrictJsonValue;
  const wrapEventHash = blake3Base64Url(canonicalizeStrictBytes(wrapEvent));
  const authorityBoundary = {
    scope_kind: (params.eventScope as Record<string, unknown>).scope_kind,
    scope_id: (params.eventScope as Record<string, unknown>).scope_id,
    event_hash: wrapEventHash,
    operation_checkpoint_sequence: params.operationCheckpoint.sequence,
    operation_checkpoint_hash: params.operationCheckpoint.checkpointHash,
    covered_event_head_sequence: params.operationCheckpoint.coveredHeadSequence,
    covered_event_head_hash: params.operationCheckpoint.coveredHeadHash,
  };
  const subjectHashes = {
    resource_hash: blake3Base64Url(canonicalizeStrictBytes(resource)),
    wrap_body_hash: wrapBodyHash,
    wrap_event_body_hash: wrapEventBodyHash,
    wrap_event_hash: wrapEventHash,
    hpke_info_hash: blake3Base64Url(info),
    aad_hash: blake3Base64Url(aad),
  };
  const signature = signPqWrapSignature({
    privateKeyMaterial: params.senderSigningPrivateKeyMaterial,
    transcript: buildPqWrapTranscript({
      ownerDeviceId: params.senderDeviceId,
      actor: base.sender,
      authorityBoundary: authorityBoundary as StrictJsonValue,
      subjectHashes,
    }),
  });

  return {
    ...base,
    event: {
      wrap_event_sequence: wrapEventSequence,
      wrap_event_hash: wrapEventHash,
      wrap_event_body_hash: wrapEventBodyHash,
    },
    hpke: {
      mode: "base",
      kem_id: KEM_ID,
      kdf_id: KDF_ID,
      aead_id: AEAD_ID,
      enc: encodeBase64Url(hpkeEnc),
      ciphertext: encodeBase64Url(ciphertext),
    },
    transcript_hash: signature.transcript_hash,
    signature,
  };
}

export function finalizeSignedPqWrapOperationCheckpoint(params: {
  record: SignedPqWrapRecord;
  operationCheckpoint: CreateSignedPqWrapParams["operationCheckpoint"];
  senderSigningPrivateKeyMaterial: CreateSignedPqWrapParams["senderSigningPrivateKeyMaterial"];
}): SignedPqWrapRecord {
  assertSignedPqWrapRecord(params.record);
  const record = {
    ...params.record,
    operation_checkpoint: {
      checkpoint_sequence: params.operationCheckpoint.sequence,
      checkpoint_hash: params.operationCheckpoint.checkpointHash,
      covered_event_head_sequence: params.operationCheckpoint.coveredHeadSequence,
      covered_event_head_hash: params.operationCheckpoint.coveredHeadHash,
    },
  };
  assertOperationCheckpointCoversWrapEvent(record);

  const enc = decodeBase64UrlStrict(record.hpke.enc, ENCAPSULATED_BYTES);
  const ciphertext = decodeBase64UrlStrict(record.hpke.ciphertext);
  const wrapBodyHash = blake3Base64Url(wrapBodyBytesForRecord(record, enc, ciphertext));
  if (wrapBodyHash !== wrapBodyHashFromEvent(record)) {
    throw new Error("signed_pq_wrap_body_hash_mismatch");
  }
  const authorityBoundary = authorityBoundaryForRecord(record);
  const subjectHashes = subjectHashesForRecord(record, enc);
  const signature = signPqWrapSignature({
    privateKeyMaterial: params.senderSigningPrivateKeyMaterial,
    transcript: buildPqWrapTranscript({
      ownerDeviceId: stringField((record.sender as Record<string, unknown>).device_id),
      actor: record.sender,
      authorityBoundary: authorityBoundary as StrictJsonValue,
      subjectHashes,
    }),
  });
  return { ...record, transcript_hash: signature.transcript_hash, signature };
}

export function signedPqWrapAdmissionCommitment(record: SignedPqWrapRecord): StrictJsonValue {
  assertSignedPqWrapRecord(record);
  return {
    protocol: record.protocol,
    protocol_version: record.protocol_version,
    suite_id: record.suite_id,
    suite_rank: record.suite_rank,
    purpose: record.purpose,
    resource: record.resource,
    sender: record.sender,
    recipient: record.recipient,
    event_scope: record.event_scope,
    event: record.event,
    operation_checkpoint: record.operation_checkpoint,
    hpke: record.hpke,
    transcript_hash: record.transcript_hash,
  };
}

export function signedPqWrapAdmissionCommitmentHash(record: SignedPqWrapRecord): string {
  return blake3Base64Url(canonicalizeStrictBytes(signedPqWrapAdmissionCommitment(record)));
}

function signedPqWrapVerificationBinding(record: SignedPqWrapRecord) {
  assertSignedPqWrapRecord(record);
  const eventBody = signedPqWrapEventBody(record) as Record<string, StrictJsonValue>;
  return {
    protocol: VERIFIED_OPERATION_PROTOCOL,
    version: VERIFIED_OPERATION_VERSION,
    sequence: record.operation_checkpoint.checkpoint_sequence,
    checkpointHash: record.operation_checkpoint.checkpoint_hash,
    coveredHeadSequence: record.operation_checkpoint.covered_event_head_sequence,
    coveredHeadHash: record.operation_checkpoint.covered_event_head_hash,
    wrapEventSequence: record.event.wrap_event_sequence,
    wrapEventHash: record.event.wrap_event_hash,
    wrapEventBodyHash: record.event.wrap_event_body_hash,
    wrapBodyHash: stringField(eventBody.wrap_body_hash),
    transcriptHash: record.transcript_hash,
    recordCommitmentHash: blake3Base64Url(
      canonicalizeStrictBytes(record as unknown as StrictJsonValue),
    ),
  } as const;
}

export function signedPqWrapEventBody(record: SignedPqWrapRecord): StrictJsonValue {
  assertSignedPqWrapRecord(record);
  return bodyFromRecord(record, eventBodyBase(record));
}

export function openSignedPqWrap(params: OpenSignedPqWrapParams): Uint8Array {
  assertSignedPqWrapRecord(params.record);
  assertVerifiedSignedPqWrapOperation(params.verifiedOperation, params.record);
  assertHybridEncryptionPrivateKeyMaterial(params.recipientPrivateKeyMaterial);
  const recipientKeyId = computeHybridEncryptionKeyId(
    publicHybridEncryptionMaterialFromPrivate(params.recipientPrivateKeyMaterial),
  );
  if (recipientKeyId !== params.record.recipient.encryption_key_id) {
    throw new Error("signed_pq_wrap_recipient_key_mismatch");
  }
  const signature = params.record.signature;
  const enc = decodeBase64UrlStrict(params.record.hpke.enc, ENCAPSULATED_BYTES);
  const ciphertext = decodeBase64UrlStrict(params.record.hpke.ciphertext);
  const actualWrapBodyHash = blake3Base64Url(
    canonicalizeStrictBytes(wrapBodyForHash(params.record, enc, ciphertext)),
  );
  if (actualWrapBodyHash !== wrapBodyHashFromEvent(params.record)) {
    throw new Error("signed_pq_wrap_body_hash_mismatch");
  }
  assertOperationCheckpointCoversWrapEvent(params.record);
  const authorityBoundary = authorityBoundaryForRecord(params.record);
  const subjectHashes = subjectHashesForRecord(params.record, enc);
  if (
    !verifyPqWrapSignature({
      publicKeyMaterial: params.senderSigningPublicKeyMaterial,
      signature,
      transcript: buildPqWrapTranscript({
        ownerDeviceId: stringField((params.record.sender as Record<string, unknown>).device_id),
        actor: params.record.sender,
        authorityBoundary: authorityBoundary as StrictJsonValue,
        subjectHashes,
      }),
    })
  ) {
    throw new Error("signed_pq_wrap_signature_invalid");
  }

  const info = hpkeInfo(params.record);
  return nativeHpkeOpen({
    privateKey: decodeBase64UrlStrict(
      params.recipientPrivateKeyMaterial.mlkem768_x25519_private,
      32,
    ),
    enc,
    info,
    aad: wrapAad(params.record, enc),
    ciphertext,
  });
}

export function assertVerifiedSignedPqWrapOperation(
  value: unknown,
  record: SignedPqWrapRecord,
): asserts value is VerifiedSignedPqWrapOperation {
  const operation = asUnknownRecord(value, "signed_pq_wrap_operation_verification_invalid");
  const expected = signedPqWrapVerificationBinding(record);
  const actualKeys = Object.keys(operation).sort().join("\n");
  const expectedKeys = Object.keys(expected).sort().join("\n");
  if (actualKeys !== expectedKeys) {
    throw new Error("signed_pq_wrap_operation_verification_invalid");
  }
  for (const [field, expectedValue] of Object.entries(expected)) {
    if (operation[field] !== expectedValue) {
      throw new Error("signed_pq_wrap_operation_verification_mismatch");
    }
  }
}

function authorityBoundaryForRecord(record: SignedPqWrapRecord): Record<string, unknown> {
  return {
    scope_kind: (record.event_scope as Record<string, unknown>).scope_kind,
    scope_id: (record.event_scope as Record<string, unknown>).scope_id,
    event_hash: record.event.wrap_event_hash,
    operation_checkpoint_sequence: record.operation_checkpoint.checkpoint_sequence,
    operation_checkpoint_hash: record.operation_checkpoint.checkpoint_hash,
    covered_event_head_sequence: record.operation_checkpoint.covered_event_head_sequence,
    covered_event_head_hash: record.operation_checkpoint.covered_event_head_hash,
  };
}

function subjectHashesForRecord(
  record: SignedPqWrapRecord,
  enc: Uint8Array,
): Record<string, string> {
  return {
    resource_hash: blake3Base64Url(canonicalizeStrictBytes(record.resource)),
    wrap_body_hash: wrapBodyHashFromEvent(record),
    wrap_event_body_hash: record.event.wrap_event_body_hash,
    wrap_event_hash: record.event.wrap_event_hash,
    hpke_info_hash: blake3Base64Url(hpkeInfo(record)),
    aad_hash: blake3Base64Url(wrapAad(record, enc)),
  };
}

function wrapBodyBytesForRecord(
  record: SignedPqWrapRecord,
  enc: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return canonicalizeStrictBytes(wrapBodyForHash(record, enc, ciphertext));
}

function assertOperationCheckpointCoversWrapEvent(record: SignedPqWrapRecord): void {
  if (record.operation_checkpoint.covered_event_head_sequence < record.event.wrap_event_sequence) {
    throw new Error("signed_pq_wrap_operation_checkpoint_does_not_anchor_event");
  }
  if (
    record.operation_checkpoint.covered_event_head_sequence === record.event.wrap_event_sequence &&
    record.operation_checkpoint.covered_event_head_hash !== record.event.wrap_event_hash
  ) {
    throw new Error("signed_pq_wrap_operation_checkpoint_head_mismatch");
  }
}

function unsignedRecordBase(params: {
  purpose: SignedPqWrapPurpose;
  resource: SignedPqWrapResource;
  sender: SignedPqWrapSender;
  recipient: SignedPqWrapRecipient;
  eventScope: SignedPqWrapEventScope;
  operationCheckpoint: CreateSignedPqWrapParams["operationCheckpoint"];
}): Omit<SignedPqWrapRecord, "event" | "hpke" | "transcript_hash" | "signature"> {
  return {
    protocol: WRAP_PROTOCOL,
    protocol_version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    suite_rank: CURRENT_SUITE_RANK,
    purpose: params.purpose,
    resource: params.resource,
    sender: params.sender,
    recipient: params.recipient,
    event_scope: params.eventScope,
    operation_checkpoint: {
      checkpoint_sequence: params.operationCheckpoint.sequence,
      checkpoint_hash: params.operationCheckpoint.checkpointHash,
      covered_event_head_sequence: params.operationCheckpoint.coveredHeadSequence,
      covered_event_head_hash: params.operationCheckpoint.coveredHeadHash,
    },
  };
}

function hpkeInfo(
  record: Pick<SignedPqWrapRecord, "purpose" | "resource" | "sender" | "recipient" | "event_scope">,
): Uint8Array {
  return canonicalizeStrictBytes({
    label: "RefMD HPKE info v1",
    protocol: WRAP_PROTOCOL,
    protocol_version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    suite_rank: CURRENT_SUITE_RANK,
    purpose: record.purpose,
    resource_hash: blake3Base64Url(canonicalizeStrictBytes(record.resource)),
    sender_user_id: record.sender.user_id,
    sender_device_id: record.sender.device_id,
    sender_signing_key_id: record.sender.signing_key_id,
    sender_key_scope_kind: record.sender.key_scope_kind,
    sender_key_scope_id: record.sender.key_scope_id,
    sender_key_checkpoint_hash: record.sender.key_checkpoint_hash,
    recipient_kind: record.recipient.recipient_kind,
    recipient_key_id: record.recipient.encryption_key_id,
    recipient_key_scope_kind: record.recipient.key_scope_kind,
    recipient_key_scope_id: record.recipient.key_scope_id,
    recipient_key_checkpoint_hash: record.recipient.key_checkpoint_hash,
    event_scope_kind: record.event_scope.scope_kind,
    event_scope_id: record.event_scope.scope_id,
  });
}

function wrapAad(
  record: Pick<SignedPqWrapRecord, "purpose" | "resource" | "sender" | "recipient" | "event_scope">,
  hpkeEnc: Uint8Array,
): Uint8Array {
  return canonicalizeStrictBytes({
    label: "RefMD PQ wrap AAD v1",
    protocol: WRAP_PROTOCOL,
    protocol_version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    suite_rank: CURRENT_SUITE_RANK,
    purpose: record.purpose,
    resource: record.resource,
    sender: record.sender,
    recipient: record.recipient,
    event_scope: record.event_scope,
    hpke: {
      mode: "base",
      kem_id: KEM_ID,
      kdf_id: KDF_ID,
      aead_id: AEAD_ID,
      enc: encodeBase64Url(hpkeEnc),
    },
  });
}

function wrapBodyForHash(
  record: ReturnType<typeof unsignedRecordBase>,
  hpkeEnc: Uint8Array,
  ciphertext: Uint8Array,
): StrictJsonValue {
  return {
    label: "RefMD PQ wrap body v1",
    protocol: WRAP_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    suite_rank: CURRENT_SUITE_RANK,
    purpose: record.purpose,
    resource: record.resource,
    sender: record.sender,
    recipient: record.recipient,
    event_scope: record.event_scope,
    hpke: {
      mode: "base",
      kem_id: KEM_ID,
      kdf_id: KDF_ID,
      aead_id: AEAD_ID,
      enc: encodeBase64Url(hpkeEnc),
      ciphertext: encodeBase64Url(ciphertext),
    },
    hpke_info_hash: blake3Base64Url(hpkeInfo(record)),
    aad_hash: blake3Base64Url(wrapAad(record, hpkeEnc)),
  };
}

function assertSignedPqWrapRecord(record: SignedPqWrapRecord): void {
  assertExactKeys(
    record as unknown as Record<string, unknown>,
    [...SIGNED_PQ_WRAP_WIRE_FIELDS],
    "signed_pq_wrap_container_keys_invalid",
  );
  if (record.protocol !== WRAP_PROTOCOL) throw new Error("signed_pq_wrap_protocol_invalid");
  if (record.protocol_version !== CURRENT_PROTOCOL_VERSION)
    throw new Error("signed_pq_wrap_version_invalid");
  if (record.suite_id !== SUITE_IDS.SIGNED_PQ_HYBRID_WRAP)
    throw new Error("signed_pq_wrap_suite_invalid");
  if (record.suite_rank !== CURRENT_SUITE_RANK)
    throw new Error("signed_pq_wrap_suite_rank_invalid");
  assertExactKeys(record.event as unknown as Record<string, unknown>, [
    "wrap_event_sequence",
    "wrap_event_hash",
    "wrap_event_body_hash",
  ]);
  assertExactKeys(record.operation_checkpoint as unknown as Record<string, unknown>, [
    "checkpoint_sequence",
    "checkpoint_hash",
    "covered_event_head_sequence",
    "covered_event_head_hash",
  ]);
  assertExactKeys(record.hpke as unknown as Record<string, unknown>, [
    "mode",
    "kem_id",
    "kdf_id",
    "aead_id",
    "enc",
    "ciphertext",
  ]);
  if (
    record.hpke.mode !== "base" ||
    record.hpke.kem_id !== KEM_ID ||
    record.hpke.kdf_id !== KDF_ID ||
    record.hpke.aead_id !== AEAD_ID
  ) {
    throw new Error("signed_pq_wrap_hpke_ids_invalid");
  }
  assertExactKeys(
    record.signature as unknown as Record<string, unknown>,
    [
      "protocol",
      "version",
      "suite_id",
      "suite_rank",
      "signing_key_id",
      "transcript_hash",
      "ed25519",
      "mldsa65",
    ],
    "signed_pq_wrap_container_keys_invalid",
  );
  if (record.signature.signing_key_id !== record.sender.signing_key_id) {
    throw new Error("signed_pq_wrap_signature_key_mismatch");
  }
  if (record.transcript_hash !== record.signature.transcript_hash) {
    throw new Error("signed_pq_wrap_transcript_hash_mismatch");
  }
  assertResourceSchema(record.purpose, record.resource);
  assertRecipientSchema(record.recipient);
}

function wrapBodyHashFromEvent(record: SignedPqWrapRecord): string {
  return stringField(bodyFromRecord(record, eventBodyBase(record)).wrap_body_hash);
}

function eventBodyBase(record: SignedPqWrapRecord): Record<string, StrictJsonValue> {
  return {
    purpose: record.purpose,
    recipient: record.recipient,
    resource: record.resource,
    resource_hash: blake3Base64Url(canonicalizeStrictBytes(record.resource)),
    sender: record.sender,
    wrap_protocol: WRAP_PROTOCOL,
    wrap_suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    wrap_suite_rank: CURRENT_SUITE_RANK,
    wrap_version: CURRENT_PROTOCOL_VERSION,
  };
}

function bodyFromRecord(
  record: SignedPqWrapRecord,
  base: Record<string, StrictJsonValue>,
): Record<string, StrictJsonValue> {
  const eventBody = {
    ...base,
    wrap_body_hash: blake3Base64Url(
      canonicalizeStrictBytes(
        wrapBodyForHash(
          record as ReturnType<typeof unsignedRecordBase>,
          decodeBase64UrlStrict(record.hpke.enc, ENCAPSULATED_BYTES),
          decodeBase64UrlStrict(record.hpke.ciphertext),
        ),
      ),
    ),
  };
  const eventBodyHash = blake3Base64Url(canonicalizeStrictBytes(eventBody));
  if (eventBodyHash !== record.event.wrap_event_body_hash) {
    throw new Error("signed_pq_wrap_event_body_hash_mismatch");
  }
  return eventBody;
}

function recipientForResource(params: {
  purpose: SignedPqWrapPurpose;
  resource: SignedPqWrapResource;
  encryption_key_id: string;
  key_scope_kind: SignedPqWrapEventScope["scope_kind"];
  key_scope_id: string;
  key_checkpoint_sequence: number;
  key_checkpoint_hash: string;
  owner_kind: HybridEncryptionPublicKeyMaterial["owner_kind"];
  owner_id: string;
}): SignedPqWrapRecipient {
  const base = {
    encryption_key_id: params.encryption_key_id,
    key_scope_kind: params.key_scope_kind,
    key_scope_id: params.key_scope_id,
    key_checkpoint_sequence: params.key_checkpoint_sequence,
    key_checkpoint_hash: params.key_checkpoint_hash,
  };
  const resource = params.resource as Record<string, StrictJsonValue>;
  switch (params.purpose) {
    case "workspace_device_kek_wrap":
      return {
        ...base,
        recipient_kind: "device",
        user_id: stringField(resource.target_user_id),
        device_id: stringField(resource.target_device_id),
      };
    case "workspace_member_kek_wrap":
      return {
        ...base,
        recipient_kind: "user_identity",
        user_id: stringField(resource.target_user_id),
      };
    case "workspace_invitation_kek_wrap":
      return {
        ...base,
        recipient_kind: "invitee",
        invitee_user_id: stringField(resource.redeemed_user_id),
        invitee_device_id: stringField(resource.redeemed_device_id),
      };
    case "guest_invitation_workspace_kek_wrap":
    case "guest_invitation_share_key_wrap":
      return {
        ...base,
        recipient_kind: "guest",
        guest_user_id: stringField(resource.guest_user_id),
        guest_device_id: stringField(resource.guest_device_id),
      };
    case "share_participant_bootstrap_wrap":
      return {
        ...base,
        recipient_kind: "share_participant_device",
        share_participant_principal_id: stringField(resource.share_participant_principal_id),
        share_participant_device_id: stringField(resource.share_participant_device_id),
      };
    case "share_link_secret_backup_wrap":
      return {
        ...base,
        recipient_kind: "device",
        user_id: stringField(resource.recipient_user_id),
        device_id: stringField(resource.recipient_device_id),
      };
  }
}

function assertRecipientSchema(recipient: SignedPqWrapRecipient): void {
  const common = [
    "encryption_key_id",
    "key_checkpoint_hash",
    "key_checkpoint_sequence",
    "key_scope_id",
    "key_scope_kind",
    "recipient_kind",
  ];
  const keysByKind: Record<SignedPqWrapRecipient["recipient_kind"], string[]> = {
    device: [...common, "user_id", "device_id"],
    user_identity: [...common, "user_id"],
    invitee: [...common, "invitee_user_id", "invitee_device_id"],
    guest: [...common, "guest_user_id", "guest_device_id"],
    share_participant_device: [
      ...common,
      "share_participant_principal_id",
      "share_participant_device_id",
    ],
  };
  const keys = keysByKind[recipient.recipient_kind];
  if (!keys) throw new Error("signed_pq_wrap_recipient_schema_invalid");
  assertExactKeys(recipient as unknown as Record<string, unknown>, keys);
}

function assertResourceSchema(
  purpose: SignedPqWrapPurpose,
  resource: StrictJsonValue,
): asserts resource is SignedPqWrapResource {
  const record = asRecord(resource);
  const schemas: Record<SignedPqWrapPurpose, string[]> = {
    workspace_device_kek_wrap: [
      "workspace_id",
      "target_user_id",
      "target_device_id",
      "kek_version",
    ],
    workspace_member_kek_wrap: ["workspace_id", "target_user_id", "kek_version"],
    share_participant_bootstrap_wrap: [
      "workspace_id",
      "share_id",
      "share_participant_principal_id",
      "share_participant_device_id",
      "scope_kind",
      "scope_id",
      "permission",
      "document_scope_hash",
      "share_session_id",
      "share_key_version",
      "dek_version",
      "bootstrap_version",
    ],
    share_link_secret_backup_wrap: [
      "workspace_id",
      "share_id",
      "token_hash",
      "scope_kind",
      "scope_id",
      "permission",
      "password_protected",
      "created_event_hash",
      "share_capability_secret_commitment",
      "password_capability_secret_commitment",
      "workspace_pin_bootstrap_hash",
      "recipient_user_id",
      "recipient_device_id",
      "recipient_encryption_key_id",
      "key_checkpoint_hash",
    ],
    workspace_invitation_kek_wrap: [
      "workspace_id",
      "invitation_id",
      "redeemed_user_id",
      "redeemed_device_id",
      "recipient_encryption_key_id",
      "role_id",
      "kek_version",
      "workspace_invitation_redeemed_event_hash",
    ],
    guest_invitation_workspace_kek_wrap: [
      "workspace_id",
      "guest_invitation_id",
      "guest_user_id",
      "guest_device_id",
      "recipient_encryption_key_id",
      "guest_grant_id",
      "scope_kind",
      "scope_id",
      "permission",
      "kek_version",
      "guest_invitation_redeemed_event_hash",
    ],
    guest_invitation_share_key_wrap: [
      "workspace_id",
      "guest_invitation_id",
      "guest_user_id",
      "guest_device_id",
      "recipient_encryption_key_id",
      "share_id",
      "scope_kind",
      "scope_id",
      "permission",
      "document_scope_hash",
      "share_key_version",
      "dek_version",
      "guest_invitation_redeemed_event_hash",
    ],
  };
  const keys = schemas[purpose];
  if (!keys) throw new Error("signed_pq_wrap_purpose_invalid");
  assertExactKeys(record, keys);
  for (const key of keys) {
    const value = record[key];
    if (key.endsWith("_version") || key === "dek_version" || key === "kek_version") {
      if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
        throw new Error("signed_pq_wrap_resource_version_invalid");
      }
    } else if (key === "password_protected") {
      if (typeof value !== "boolean") throw new Error("signed_pq_wrap_resource_boolean_invalid");
    } else if (typeof value !== "string" || value.length === 0) {
      throw new Error("signed_pq_wrap_resource_string_invalid");
    }
  }
  if (
    "scope_kind" in record &&
    !["document", "folder", "workspace"].includes(record.scope_kind as string)
  ) {
    throw new Error("signed_pq_wrap_resource_scope_invalid");
  }
  if ("permission" in record && !["view", "edit"].includes(record.permission as string)) {
    throw new Error("signed_pq_wrap_resource_permission_invalid");
  }
  if (
    [
      "share_participant_bootstrap_wrap",
      "share_link_secret_backup_wrap",
      "guest_invitation_share_key_wrap",
    ].includes(purpose)
  ) {
    if (!["document", "folder"].includes(record.scope_kind as string)) {
      throw new Error("signed_pq_wrap_resource_scope_invalid");
    }
    if (record.scope_id === "none") {
      throw new Error("signed_pq_wrap_resource_scope_invalid");
    }
    assertResourceIdsNotNone(record, [
      "workspace_id",
      "share_id",
      "scope_id",
      "guest_invitation_id",
      "guest_user_id",
      "guest_device_id",
      "recipient_device_id",
      "recipient_user_id",
      "share_participant_device_id",
      "share_participant_principal_id",
      "share_session_id",
    ]);
    assertBase64UrlHashFields(record, [
      "document_scope_hash",
      "created_event_hash",
      "key_checkpoint_hash",
      "share_capability_secret_commitment",
      "token_hash",
      "workspace_pin_bootstrap_hash",
      "guest_invitation_redeemed_event_hash",
    ]);
    assertPasswordCapabilityCommitment(record);
  }
  if (purpose === "guest_invitation_workspace_kek_wrap") {
    if (record.scope_kind !== "workspace" || record.scope_id !== "none") {
      throw new Error("signed_pq_wrap_guest_workspace_resource_invalid");
    }
  }
}

function assertResourceIdsNotNone(record: Record<string, unknown>, keys: string[]): void {
  for (const key of keys) {
    if (!(key in record)) continue;
    if (record[key] === "none") throw new Error("signed_pq_wrap_resource_id_invalid");
  }
}

function assertBase64UrlHashFields(record: Record<string, unknown>, keys: string[]): void {
  for (const key of keys) {
    if (!(key in record)) continue;
    const value = record[key];
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
      throw new Error("signed_pq_wrap_resource_hash_invalid");
    }
  }
}

function assertPasswordCapabilityCommitment(record: Record<string, unknown>): void {
  if (!("password_capability_secret_commitment" in record)) return;
  const value = record.password_capability_secret_commitment;
  if (record.password_protected === false && value === "none") return;
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error("signed_pq_wrap_resource_hash_invalid");
  }
}

function asRecord(value: StrictJsonValue): Record<string, StrictJsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("signed_pq_wrap_resource_invalid");
  }
  return value as Record<string, StrictJsonValue>;
}

function asUnknownRecord(value: unknown, error: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(error);
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(
  record: Record<string, unknown>,
  keys: string[],
  error = "signed_pq_wrap_resource_keys_invalid",
): void {
  const actual = Object.keys(record).sort().join("\n");
  const expected = [...keys].sort().join("\n");
  if (actual !== expected) throw new Error(error);
}

function assertAllowedKeys(record: Record<string, unknown>, keys: readonly string[]): void {
  const allowed = new Set(keys);
  if (Object.keys(record).some((key) => !allowed.has(key))) {
    throw new Error("signed_pq_wrap_container_keys_invalid");
  }
}

function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0)
    throw new Error("signed_pq_wrap_string_invalid");
  return value;
}
