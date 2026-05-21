import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import type { components } from "@/shared/api/schema";
import { constantTimeEqual, decodeBase64UrlStrict, encodeBase64Url, randomBytes } from "./encoding";
import { blake3Base64Url } from "./hash";
import {
  assertNonZeroSharedSecret,
  assertRecord,
  concatBytes,
  deriveAkeSecret,
  deriveDeliveryKey,
  initialDeliveryAad,
  numberField,
  purposeContext,
  purposeDirectory,
  requiredComponentsValid,
  stringField,
} from "./initial-ake-helpers";
import { canonicalizeStrictBytes, parseJsonStrictBytes, type StrictJsonValue } from "./jcs";
import {
  buildInitialKeyDeliveryTranscript,
  buildInitiatorAkeCommitmentTranscript,
  buildResponderPrekeyTranscript,
  computeSigningKeyId,
  publicKeyMaterialFromPrivate,
  signInitialKeyDeliverySignature,
  signInitiatorAkeCommitmentSignature,
  signResponderPrekeySignature,
  verifyInitialKeyDeliverySignature,
  verifyInitiatorAkeCommitmentSignature,
  verifyResponderPrekeySignature,
  type HybridSignature,
  type HybridSigningPrivateKeyMaterial,
  type HybridSigningPublicKeyMaterial,
} from "./signature";
import type { InitialAkePurpose } from "./initial-ake-types";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";

const RESPONDER_PREKEY_PROTOCOL = "refmd.responder-prekey";
const AKE_PROTOCOL = "refmd.initial-hybrid-key-agreement";
const COMMITMENT_PROTOCOL = "refmd.initiator-ake-commitment";
const DELIVERY_PROTOCOL = "refmd.initial-key-delivery";
const X25519_PUBLIC_BYTES = 32;
const X25519_PRIVATE_BYTES = 32;
const MLKEM_PUBLIC_BYTES = 1184;
const MLKEM_PRIVATE_BYTES = 2400;
const MLKEM_CIPHERTEXT_BYTES = 1088;
const RESPONDER_PREKEY_PAYLOAD_KEYS = [
  "expires_event_sequence",
  "issued_at_event_sequence",
  "mlkem768_ephemeral_public",
  "mlkem768_ephemeral_public_hash",
  "operation_id",
  "prekey_id",
  "protocol",
  "purpose",
  "responder_device_id",
  "responder_signer_kind",
  "responder_signing_key_id",
  "responder_user_id",
  "server_challenge",
  "version",
  "x25519_ephemeral_public",
] as const;
const INITIAL_KEY_DELIVERY_KEYS = [
  "aead",
  "authority",
  "initial_delivery_suite_id",
  "initial_delivery_suite_rank",
  "metadata",
  "protocol",
  "purpose",
  "signature",
  "variant",
  "version",
] as const;
const INITIAL_DELIVERY_AEAD_KEYS = [
  "ciphertext",
  "ciphertext_hash",
  "nonce",
  "suite_id",
  "suite_rank",
] as const;
const INITIAL_DELIVERY_AUTHORITY_KEYS = ["sender_authority_kind"] as const;
const INITIAL_DELIVERY_COMMON_METADATA_KEYS = [
  "ake_transcript_hash",
  "context_hash",
  "delivery_id",
  "initiator_commitment_hash",
  "key_checkpoint_hash",
  "key_confirmation_hash",
  "key_kind",
  "key_version",
  "payload_kind",
  "recipient_challenge_hash",
  "recipient_device_id",
  "recipient_encryption_key_id",
  "resource_hash",
  "sender_device_id",
  "signing_key_id",
  "suite_id",
  "suite_rank",
] as const;
const INITIAL_AKE_ARTIFACT_KEYS = [
  "ake_suite_id",
  "ake_suite_rank",
  "initiator_commitment",
  "initiator_commitment_signature",
  "initiator_confirmation",
  "protocol",
  "purpose",
  "responder_confirmation",
  "transcript",
  "transcript_hash",
  "version",
] as const;
const INITIAL_AKE_TRANSCRIPT_KEYS = [
  "ake_suite_id",
  "ake_suite_rank",
  "context",
  "directory",
  "initiator",
  "protocol",
  "purpose",
  "required_components",
  "responder",
  "version",
] as const;
const INITIAL_AKE_TRANSCRIPT_INITIATOR_KEYS = [
  "device_id",
  "initiator_commitment_hash",
  "mlkem768_enc",
  "signing_key_id",
  "user_id",
  "x25519_ephemeral_public",
] as const;
const INITIAL_AKE_TRANSCRIPT_RESPONDER_KEYS = [
  "device_id",
  "mlkem768_ephemeral_public_hash",
  "prekey_hash",
  "prekey_id",
  "signer_kind",
  "signing_key_id",
  "user_id",
  "x25519_ephemeral_public",
] as const;
const INITIATOR_COMMITMENT_KEYS = [
  "ake_inputs",
  "ake_suite_id",
  "ake_suite_rank",
  "context_hash",
  "directory_hash",
  "initial_delivery_suite_id",
  "initial_delivery_suite_rank",
  "initiator",
  "operation_id",
  "protocol",
  "purpose",
  "recipient_hash",
  "server_challenge",
  "version",
] as const;
const INITIATOR_COMMITMENT_AKE_INPUT_KEYS = [
  "mlkem768_enc",
  "responder_prekey_hash",
  "x25519_ephemeral_public",
] as const;
const INITIATOR_COMMITMENT_INITIATOR_KEYS = [
  "device_id",
  "encryption_key_id",
  "pending_registration_binding_hash",
  "signer_kind",
  "signing_key_id",
  "user_id",
] as const;
const INITIAL_AKE_UMK_CONTEXT_KEYS = [
  "challenge",
  "distribution_id",
  "operation_id",
  "owner_user_id",
  "purpose",
  "recipient_device_id",
  "target_key_kind",
  "target_key_version",
] as const;
const INITIAL_AKE_APPROVAL_CONTEXT_KEYS = [
  "approved_device_id",
  "challenge",
  "operation_id",
  "owner_user_id",
  "purpose",
  "registration_id",
  "target_key_kind",
  "target_key_version",
  "workspace_id",
] as const;
const INITIAL_AKE_TRUST_CONTEXT_KEYS = [
  "challenge",
  "operation_id",
  "owner_user_id",
  "purpose",
  "source_device_id",
  "target_device_id",
  "target_payload_kind",
  "transfer_scope_hash",
  "trust_transfer_id",
] as const;
const INITIAL_AKE_UMK_DIRECTORY_KEYS = [
  "allowed_suite_ids_hash",
  "min_suite_rank",
  "suite_policy_version",
  "user_checkpoint_hash",
  "user_event_head_hash",
] as const;
const INITIAL_AKE_APPROVAL_DIRECTORY_KEYS = [
  "allowed_suite_ids_hash",
  "event_head_hash",
  "min_suite_rank",
  "suite_policy_version",
  "user_checkpoint_hash",
  "workspace_checkpoint_hash",
] as const;
const INITIAL_AKE_TRUST_DIRECTORY_KEYS = [
  "allowed_suite_ids_hash",
  "min_suite_rank",
  "suite_policy_version",
  "user_checkpoint_hash",
  "user_event_head_hash",
  "workspace_pins_hash",
] as const;
export type { InitialAkePurpose } from "./initial-ake-types";

export interface InitialAkeResponderPrekeyPrivate {
  prekey_id: string;
  operation_id: string;
  purpose: InitialAkePurpose;
  x25519_private: string;
  mlkem768_private: string;
}

export interface InitialAkeResponderPrekeyRecord {
  payload: StrictJsonValue;
  signature: HybridSignature;
}

export type InitialAkeArtifact = components["schemas"]["InitialAkeArtifact"];
export type InitialKeyDeliveryRecord = components["schemas"]["InitialKeyDeliveryRecord"];

export function generateInitialAkeResponderPrekey(params: {
  purpose: InitialAkePurpose;
  operationId: string;
  userId: string;
  deviceId: string;
  serverChallenge?: string;
  issuedAtEventSequence: number;
  expiresEventSequence: number;
  signingPrivateKeyMaterial: HybridSigningPrivateKeyMaterial;
}): {
  record: InitialAkeResponderPrekeyRecord;
  privatePrekey: InitialAkeResponderPrekeyPrivate;
} {
  const x25519Private = x25519.utils.randomSecretKey();
  const x25519Public = x25519.getPublicKey(x25519Private);
  const mlkem = ml_kem768.keygen();
  const prekeyId = crypto.randomUUID();
  const publicKeyMaterial = publicKeyMaterialFromPrivate(params.signingPrivateKeyMaterial);
  const signingKeyId = computeSigningKeyId(publicKeyMaterial);
  const payload = {
    protocol: RESPONDER_PREKEY_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    purpose: params.purpose,
    prekey_id: prekeyId,
    responder_signer_kind: "device",
    responder_user_id: params.userId,
    responder_device_id: params.deviceId,
    responder_signing_key_id: signingKeyId,
    x25519_ephemeral_public: encodeBase64Url(x25519Public),
    mlkem768_ephemeral_public: encodeBase64Url(mlkem.publicKey),
    mlkem768_ephemeral_public_hash: blake3Base64Url(mlkem.publicKey),
    operation_id: params.operationId,
    issued_at_event_sequence: params.issuedAtEventSequence,
    expires_event_sequence: params.expiresEventSequence,
    server_challenge: params.serverChallenge ?? encodeBase64Url(randomBytes(32)),
  } as const;
  const signature = signResponderPrekeySignature({
    privateKeyMaterial: params.signingPrivateKeyMaterial,
    transcript: buildResponderPrekeyTranscript({
      ownerDeviceId: params.deviceId,
      prekeyPayload: payload,
      responder: {
        user_id: params.userId,
        device_id: params.deviceId,
        signing_key_id: signingKeyId,
        key_scope_kind: "user",
        key_scope_id: params.userId,
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: blake3Base64Url(canonicalizeStrictBytes(payload)),
      },
      freshness: {
        purpose: params.purpose,
        prekey_id: prekeyId,
        operation_id: params.operationId,
        issued_at_event_sequence: payload.issued_at_event_sequence,
        expires_event_sequence: payload.expires_event_sequence,
        server_challenge: payload.server_challenge,
      },
    }),
  });

  return {
    record: { payload, signature },
    privatePrekey: {
      prekey_id: prekeyId,
      operation_id: params.operationId,
      purpose: params.purpose,
      x25519_private: encodeBase64Url(x25519Private),
      mlkem768_private: encodeBase64Url(mlkem.secretKey),
    },
  };
}

export function verifyInitialAkeResponderPrekey(params: {
  record: InitialAkeResponderPrekeyRecord;
  responderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
}): void {
  const payload = assertRecord(params.record.payload, "responder_prekey_payload_invalid");
  assertExactKeys(payload, RESPONDER_PREKEY_PAYLOAD_KEYS, "responder_prekey_payload_invalid");
  if (
    payload.protocol !== RESPONDER_PREKEY_PROTOCOL ||
    payload.version !== CURRENT_PROTOCOL_VERSION
  ) {
    throw new Error("responder_prekey_protocol_invalid");
  }
  if (payload.responder_signer_kind !== "device") {
    throw new Error("responder_prekey_signer_invalid");
  }
  const deviceId = stringField(payload.responder_device_id, "responder_device_id_invalid");
  const userId = stringField(payload.responder_user_id, "responder_user_id_invalid");
  const signingKeyId = stringField(
    payload.responder_signing_key_id,
    "responder_signing_key_id_invalid",
  );
  if (signingKeyId !== computeSigningKeyId(params.responderSigningPublicKeyMaterial)) {
    throw new Error("responder_prekey_signing_key_mismatch");
  }
  if (
    params.responderSigningPublicKeyMaterial.owner_kind !== "device" ||
    params.responderSigningPublicKeyMaterial.owner_id !== deviceId
  ) {
    throw new Error("responder_prekey_signer_mismatch");
  }
  const x25519Public = decodeBase64UrlStrict(
    stringField(payload.x25519_ephemeral_public, "responder_prekey_x25519_invalid"),
    X25519_PUBLIC_BYTES,
  );
  const mlkemPublic = decodeBase64UrlStrict(
    stringField(payload.mlkem768_ephemeral_public, "responder_prekey_mlkem_invalid"),
    MLKEM_PUBLIC_BYTES,
  );
  const mlkemPublicHash = stringField(
    payload.mlkem768_ephemeral_public_hash,
    "responder_prekey_mlkem_hash_invalid",
  );
  if (mlkemPublicHash !== blake3Base64Url(mlkemPublic)) {
    throw new Error("responder_prekey_mlkem_hash_mismatch");
  }
  const serverChallenge = stringField(
    payload.server_challenge,
    "responder_prekey_challenge_invalid",
  );
  decodeBase64UrlStrict(serverChallenge, 32);
  if (x25519Public.length !== X25519_PUBLIC_BYTES) {
    throw new Error("responder_prekey_x25519_invalid");
  }
  const issuedAtEventSequence = numberField(
    payload.issued_at_event_sequence,
    "responder_prekey_issued_sequence_invalid",
  );
  const expiresEventSequence = numberField(
    payload.expires_event_sequence,
    "responder_prekey_expires_sequence_invalid",
  );
  if (issuedAtEventSequence >= expiresEventSequence) {
    throw new Error("responder_prekey_sequence_invalid");
  }
  const purpose = stringField(payload.purpose, "responder_prekey_purpose_invalid");
  if (
    purpose !== "umk_distribution" &&
    purpose !== "device_approval_kek_initial" &&
    purpose !== "trust_transfer"
  ) {
    throw new Error("responder_prekey_purpose_invalid");
  }
  const transcript = buildResponderPrekeyTranscript({
    ownerDeviceId: deviceId,
    prekeyPayload: params.record.payload,
    responder: {
      user_id: userId,
      device_id: deviceId,
      signing_key_id: signingKeyId,
      key_scope_kind: "user",
      key_scope_id: userId,
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: blake3Base64Url(canonicalizeStrictBytes(params.record.payload)),
    },
    freshness: {
      purpose,
      prekey_id: stringField(payload.prekey_id, "responder_prekey_id_invalid"),
      operation_id: stringField(payload.operation_id, "responder_prekey_operation_invalid"),
      issued_at_event_sequence: issuedAtEventSequence,
      expires_event_sequence: expiresEventSequence,
      server_challenge: serverChallenge,
    },
  });
  if (
    !verifyResponderPrekeySignature({
      publicKeyMaterial: params.responderSigningPublicKeyMaterial,
      signature: params.record.signature,
      transcript,
    })
  ) {
    throw new Error("responder_prekey_signature_invalid");
  }
}

export function createInitialAkeUmkDelivery(params: {
  umk: Uint8Array;
  purpose?: InitialAkePurpose;
  plaintext?: Uint8Array;
  payloadKind?: "umk" | "workspace_kek" | "trust_state_bundle";
  keyKind?: "umk" | "kek" | "trust_state_bundle";
  workspaceId?: string;
  keyVersion?: number;
  userId: string;
  senderDeviceId: string;
  senderEncryptionKeyId: string;
  recipientDeviceId: string;
  recipientEncryptionKeyId: string;
  responderPrekey: InitialAkeResponderPrekeyRecord;
  responderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  senderSigningPrivateKeyMaterial: HybridSigningPrivateKeyMaterial;
  resourceHash: string;
  keyCheckpointHash: string;
  keyEventHeadHash: string;
  userCheckpointHash?: string;
  workspaceCheckpointHash?: string;
  workspaceEventHeadHash?: string;
  workspacePinsHash?: string;
  documentRollbackPinSetHash?: string;
  pendingRegistrationBindingHash: string;
}): {
  initialAke: InitialAkeArtifact;
  initialKeyDelivery: InitialKeyDeliveryRecord;
} {
  const purpose = params.purpose ?? "umk_distribution";
  const plaintext = params.plaintext ?? params.umk;
  const payloadKind = params.payloadKind ?? "umk";
  const keyKind = params.keyKind ?? "umk";
  const keyVersion = params.keyVersion ?? 1;
  const prekey = assertRecord(params.responderPrekey.payload, "responder_prekey_payload_invalid");
  if (prekey.purpose !== purpose) throw new Error("responder_prekey_purpose_mismatch");
  verifyInitialAkeResponderPrekey({
    record: params.responderPrekey,
    responderSigningPublicKeyMaterial: params.responderSigningPublicKeyMaterial,
  });
  const prekeyHash = blake3Base64Url(canonicalizeStrictBytes(params.responderPrekey.payload));
  const initiatorPrivate = x25519.utils.randomSecretKey();
  const initiatorPublic = x25519.getPublicKey(initiatorPrivate);
  const responderX25519Public = decodeBase64UrlStrict(
    stringField(prekey.x25519_ephemeral_public, "responder_x25519_prekey_invalid"),
    X25519_PUBLIC_BYTES,
  );
  const responderMlkemPublic = decodeBase64UrlStrict(
    stringField(prekey.mlkem768_ephemeral_public, "responder_mlkem_prekey_invalid"),
    MLKEM_PUBLIC_BYTES,
  );
  const mlkem = ml_kem768.encapsulate(responderMlkemPublic);
  const dh = x25519.getSharedSecret(initiatorPrivate, responderX25519Public);
  assertNonZeroSharedSecret(dh);
  const senderPublic = publicKeyMaterialFromPrivate(params.senderSigningPrivateKeyMaterial);
  const senderSigningKeyId = computeSigningKeyId(senderPublic);
  const operationId = stringField(prekey.operation_id, "operation_id_invalid");
  const context = purposeContext({
    purpose,
    userId: params.userId,
    senderDeviceId: params.senderDeviceId,
    recipientDeviceId: params.recipientDeviceId,
    workspaceId: params.workspaceId,
    operationId,
    targetKeyKind: keyKind,
    targetKeyVersion: keyVersion,
    challenge: stringField(prekey.server_challenge, "server_challenge_invalid"),
  });
  const contextRecord = context as Record<string, unknown>;
  const directory = purposeDirectory({
    purpose,
    userCheckpointHash: params.userCheckpointHash ?? params.keyCheckpointHash,
    userEventHeadHash: params.keyEventHeadHash,
    workspaceCheckpointHash: params.workspaceCheckpointHash ?? params.keyCheckpointHash,
    workspaceEventHeadHash: params.workspaceEventHeadHash ?? params.keyEventHeadHash,
    workspacePinsHash: params.workspacePinsHash,
  });
  const commitmentPayload = {
    protocol: COMMITMENT_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    ake_suite_id: SUITE_IDS.INITIAL_AKE,
    ake_suite_rank: CURRENT_SUITE_RANK,
    initial_delivery_suite_id: SUITE_IDS.INITIAL_DELIVERY,
    initial_delivery_suite_rank: CURRENT_SUITE_RANK,
    purpose,
    operation_id: operationId,
    initiator: {
      signer_kind: "active_device",
      user_id: params.userId,
      device_id: params.senderDeviceId,
      signing_key_id: senderSigningKeyId,
      encryption_key_id: params.senderEncryptionKeyId,
      pending_registration_binding_hash: params.pendingRegistrationBindingHash,
    },
    ake_inputs: {
      x25519_ephemeral_public: encodeBase64Url(initiatorPublic),
      mlkem768_enc: encodeBase64Url(mlkem.cipherText),
      responder_prekey_hash: prekeyHash,
    },
    context_hash: blake3Base64Url(canonicalizeStrictBytes(context)),
    directory_hash: blake3Base64Url(canonicalizeStrictBytes(directory)),
    recipient_hash: blake3Base64Url(
      canonicalizeStrictBytes({
        user_id: params.userId,
        device_id: params.recipientDeviceId,
        encryption_key_id: params.recipientEncryptionKeyId,
        prekey_hash: prekeyHash,
      }),
    ),
    server_challenge: stringField(contextRecord.challenge, "server_challenge_invalid"),
  } as const;
  const commitmentSignature = signInitiatorAkeCommitmentSignature({
    privateKeyMaterial: params.senderSigningPrivateKeyMaterial,
    transcript: buildInitiatorAkeCommitmentTranscript({
      ownerDeviceId: params.senderDeviceId,
      commitmentPayload,
      initiator: commitmentPayload.initiator,
      akeInputs: commitmentPayload.ake_inputs,
      binding: {
        operation_id: operationId,
        context_hash: commitmentPayload.context_hash,
        directory_hash: commitmentPayload.directory_hash,
        recipient_hash: commitmentPayload.recipient_hash,
        server_challenge: stringField(contextRecord.challenge, "server_challenge_invalid"),
      },
    }),
  });
  const commitmentHash = blake3Base64Url(canonicalizeStrictBytes(commitmentPayload));
  const transcript = {
    protocol: AKE_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    ake_suite_id: SUITE_IDS.INITIAL_AKE,
    ake_suite_rank: CURRENT_SUITE_RANK,
    required_components: [
      "x25519-ephemeral",
      "mlkem768-ephemeral",
      "hkdf-sha256",
      "initiator-ake-commitment",
      "responder-prekey-signature",
    ] as const,
    purpose,
    initiator: {
      user_id: params.userId,
      device_id: params.senderDeviceId,
      signing_key_id: senderSigningKeyId,
      x25519_ephemeral_public: encodeBase64Url(initiatorPublic),
      mlkem768_enc: encodeBase64Url(mlkem.cipherText),
      initiator_commitment_hash: commitmentHash,
    },
    responder: {
      signer_kind: "device",
      user_id: params.userId,
      device_id: params.recipientDeviceId,
      signing_key_id: stringField(
        prekey.responder_signing_key_id,
        "responder_signing_key_id_invalid",
      ),
      x25519_ephemeral_public: stringField(
        prekey.x25519_ephemeral_public,
        "responder_x25519_invalid",
      ),
      mlkem768_ephemeral_public_hash: stringField(
        prekey.mlkem768_ephemeral_public_hash,
        "responder_mlkem_hash_invalid",
      ),
      prekey_id: stringField(prekey.prekey_id, "prekey_id_invalid"),
      prekey_hash: prekeyHash,
    },
    context,
    directory,
  } as const;
  const transcriptBytes = canonicalizeStrictBytes(transcript as unknown as StrictJsonValue);
  const transcriptHashBytes = blake3(transcriptBytes);
  const transcriptHash = encodeBase64Url(transcriptHashBytes);
  const secret = deriveAkeSecret(dh, mlkem.sharedSecret, transcriptHashBytes, purpose);
  const initiatorConfirmation = hmac(
    sha256,
    secret,
    concatBytes(new TextEncoder().encode("initiator-confirm"), transcriptHashBytes),
  );
  const responderConfirmation = hmac(
    sha256,
    secret,
    concatBytes(new TextEncoder().encode("responder-confirm"), transcriptHashBytes),
  );
  const contextHash = blake3Base64Url(canonicalizeStrictBytes(context));
  const deliveryKey = deriveDeliveryKey(secret, transcriptHashBytes, contextHash, purpose);
  const nonce = randomBytes(24);
  const deliveryId = crypto.randomUUID();
  const metadata = {
    delivery_id: deliveryId,
    sender_device_id: params.senderDeviceId,
    recipient_device_id: params.recipientDeviceId,
    ake_transcript_hash: transcriptHash,
    context_hash: contextHash,
    initiator_commitment_hash: commitmentHash,
    recipient_challenge_hash: blake3Base64Url(
      decodeBase64UrlStrict(stringField(contextRecord.challenge, "server_challenge_invalid"), 32),
    ),
    recipient_encryption_key_id: params.recipientEncryptionKeyId,
    key_confirmation_hash: blake3Base64Url(
      concatBytes(initiatorConfirmation, responderConfirmation),
    ),
    signing_key_id: senderSigningKeyId,
    key_checkpoint_hash: params.keyCheckpointHash,
    ...(params.documentRollbackPinSetHash
      ? { document_rollback_pin_set_hash: params.documentRollbackPinSetHash }
      : {}),
    ...(params.workspaceId ? { workspace_id: params.workspaceId } : {}),
    key_version: keyVersion,
    payload_kind: payloadKind,
    key_kind: keyKind,
    resource_hash: params.resourceHash,
    suite_id: SUITE_IDS.INITIAL_DELIVERY,
    suite_rank: CURRENT_SUITE_RANK,
  } as const;
  const aadBase = initialDeliveryAad({
    purpose,
    deliveryId,
    transcriptHash,
    contextHash,
    commitmentHash,
    senderHash: blake3Base64Url(
      canonicalizeStrictBytes({ user_id: params.userId, device_id: params.senderDeviceId }),
    ),
    recipientHash: commitmentPayload.recipient_hash,
    payloadMetadataHash: blake3Base64Url(canonicalizeStrictBytes(metadata)),
  });
  const ciphertext = xchacha20poly1305(deliveryKey, nonce, aadBase).encrypt(plaintext);
  const aead = {
    suite_id: SUITE_IDS.INITIAL_DELIVERY,
    suite_rank: CURRENT_SUITE_RANK,
    nonce: encodeBase64Url(nonce),
    ciphertext: encodeBase64Url(ciphertext),
    ciphertext_hash: blake3Base64Url(ciphertext),
  } as const;
  const authority = { sender_authority_kind: "device" } as const;
  const signingBody = {
    protocol: DELIVERY_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    purpose,
    variant: purpose,
    initial_delivery_suite_id: SUITE_IDS.INITIAL_DELIVERY,
    initial_delivery_suite_rank: CURRENT_SUITE_RANK,
    metadata,
    aead,
    authority,
  } as const;
  const deliverySignature = signInitialKeyDeliverySignature({
    privateKeyMaterial: params.senderSigningPrivateKeyMaterial,
    transcript: buildInitialKeyDeliveryTranscript({
      ownerDeviceId: params.senderDeviceId,
      variant: purpose,
      deliverySigningBody: signingBody,
      sender: {
        user_id: params.userId,
        device_id: params.senderDeviceId,
        signing_key_id: senderSigningKeyId,
      },
      recipient: {
        user_id: params.userId,
        device_id: params.recipientDeviceId,
        encryption_key_id: params.recipientEncryptionKeyId,
      },
      ake: {
        ake_transcript_hash: transcriptHash,
        initiator_commitment_hash: commitmentHash,
        purpose,
        operation_id: operationId,
      },
      delivery: {
        delivery_id: deliveryId,
        context_hash: contextHash,
        payload_kind: payloadKind,
        ciphertext_hash: aead.ciphertext_hash,
      },
      authority,
    }),
  });
  return {
    initialAke: {
      protocol: AKE_PROTOCOL,
      version: CURRENT_PROTOCOL_VERSION,
      ake_suite_id: SUITE_IDS.INITIAL_AKE,
      ake_suite_rank: CURRENT_SUITE_RANK,
      purpose,
      transcript,
      transcript_hash: transcriptHash,
      initiator_commitment: commitmentPayload,
      initiator_commitment_signature: commitmentSignature,
      initiator_confirmation: encodeBase64Url(initiatorConfirmation),
      responder_confirmation: encodeBase64Url(responderConfirmation),
    } as unknown as InitialAkeArtifact,
    initialKeyDelivery: {
      ...signingBody,
      signature: deliverySignature,
    } as InitialKeyDeliveryRecord,
  };
}

export function createInitialAkeKekDelivery(
  params: Omit<
    Parameters<typeof createInitialAkeUmkDelivery>[0],
    "umk" | "purpose" | "payloadKind" | "keyKind" | "plaintext"
  > & {
    kek: Uint8Array;
    workspaceId: string;
    keyVersion: number;
  },
) {
  return createInitialAkeUmkDelivery({
    ...params,
    umk: params.kek,
    plaintext: params.kek,
    purpose: "device_approval_kek_initial",
    payloadKind: "workspace_kek",
    keyKind: "kek",
    workspaceId: params.workspaceId,
    keyVersion: params.keyVersion,
  });
}

export function createInitialAkeDeviceStateTransferDelivery(
  params: Omit<
    Parameters<typeof createInitialAkeUmkDelivery>[0],
    "umk" | "purpose" | "payloadKind" | "keyKind" | "plaintext"
  > & {
    deviceStateBundle: StrictJsonValue;
    documentRollbackPinSetHash: string;
  },
) {
  if (!params.documentRollbackPinSetHash)
    throw new Error("document_rollback_pin_set_hash_required");
  const plaintext = canonicalizeStrictBytes(params.deviceStateBundle);
  return createInitialAkeUmkDelivery({
    ...params,
    umk: plaintext,
    plaintext,
    purpose: "trust_transfer",
    payloadKind: "trust_state_bundle",
    keyKind: "trust_state_bundle",
    documentRollbackPinSetHash: params.documentRollbackPinSetHash,
  });
}

export function openInitialAkeUmkDelivery(params: {
  initialAke: InitialAkeArtifact;
  initialKeyDelivery: InitialKeyDeliveryRecord;
  privatePrekey: InitialAkeResponderPrekeyPrivate;
  senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
}): Uint8Array {
  const initialAkeRecord = assertRecord(params.initialAke, "initial_ake_payload_invalid");
  assertExactKeys(initialAkeRecord, INITIAL_AKE_ARTIFACT_KEYS, "initial_ake_payload_invalid");
  const deliveryRecord = assertRecord(
    params.initialKeyDelivery,
    "initial_delivery_payload_invalid",
  );
  if (
    params.initialAke.protocol !== AKE_PROTOCOL ||
    params.initialKeyDelivery.protocol !== DELIVERY_PROTOCOL
  ) {
    throw new Error("initial_ake_protocol_invalid");
  }
  if (
    params.initialAke.version !== CURRENT_PROTOCOL_VERSION ||
    params.initialAke.ake_suite_id !== SUITE_IDS.INITIAL_AKE ||
    params.initialAke.ake_suite_rank !== CURRENT_SUITE_RANK
  ) {
    throw new Error("initial_ake_suite_not_allowed");
  }
  const purpose = stringField(
    params.initialAke.purpose,
    "initial_ake_purpose_invalid",
  ) as InitialAkePurpose;
  if (params.privatePrekey.purpose !== purpose) {
    throw new Error("initial_ake_prekey_purpose_mismatch");
  }
  if (
    params.initialKeyDelivery.version !== CURRENT_PROTOCOL_VERSION ||
    params.initialKeyDelivery.purpose !== purpose ||
    params.initialKeyDelivery.variant !== purpose
  ) {
    throw new Error("initial_delivery_purpose_invalid");
  }
  const transcriptHashBytes = blake3(canonicalizeStrictBytes(params.initialAke.transcript));
  const transcriptHash = encodeBase64Url(transcriptHashBytes);
  if (params.initialAke.transcript_hash !== transcriptHash) {
    throw new Error("initial_ake_transcript_hash_mismatch");
  }
  const transcript = assertRecord(params.initialAke.transcript, "initial_ake_transcript_invalid");
  assertExactKeys(transcript, INITIAL_AKE_TRANSCRIPT_KEYS, "initial_ake_transcript_invalid");
  if (
    transcript.protocol !== AKE_PROTOCOL ||
    transcript.version !== CURRENT_PROTOCOL_VERSION ||
    transcript.ake_suite_id !== SUITE_IDS.INITIAL_AKE ||
    transcript.ake_suite_rank !== CURRENT_SUITE_RANK ||
    transcript.purpose !== purpose ||
    !requiredComponentsValid(transcript.required_components)
  ) {
    throw new Error("initial_ake_transcript_policy_invalid");
  }
  const initiator = assertRecord(transcript.initiator, "initial_ake_initiator_invalid");
  const responder = assertRecord(transcript.responder, "initial_ake_responder_invalid");
  const contextRecord = assertRecord(transcript.context, "initial_ake_context_invalid");
  const directoryRecord = assertRecord(transcript.directory, "initial_ake_directory_invalid");
  assertExactKeys(
    initiator,
    INITIAL_AKE_TRANSCRIPT_INITIATOR_KEYS,
    "initial_ake_initiator_invalid",
  );
  assertExactKeys(
    responder,
    INITIAL_AKE_TRANSCRIPT_RESPONDER_KEYS,
    "initial_ake_responder_invalid",
  );
  assertInitialAkeContextKeys(purpose, contextRecord);
  assertInitialAkeDirectoryKeys(purpose, directoryRecord);
  if (
    params.privatePrekey.prekey_id !== responder.prekey_id ||
    params.privatePrekey.operation_id !== (contextRecord.operation_id as string)
  ) {
    throw new Error("initial_ake_prekey_mismatch");
  }
  const commitment = params.initialAke.initiator_commitment;
  const commitmentRecord = assertRecord(commitment, "initiator_commitment_invalid");
  assertExactKeys(commitmentRecord, INITIATOR_COMMITMENT_KEYS, "initiator_commitment_invalid");
  const commitmentInitiator = assertRecord(commitmentRecord.initiator, "initiator_invalid");
  const commitmentAkeInputs = assertRecord(
    commitmentRecord.ake_inputs,
    "initiator_commitment_ake_inputs_invalid",
  );
  assertExactKeys(commitmentInitiator, INITIATOR_COMMITMENT_INITIATOR_KEYS, "initiator_invalid");
  assertExactKeys(
    commitmentAkeInputs,
    INITIATOR_COMMITMENT_AKE_INPUT_KEYS,
    "initiator_commitment_ake_inputs_invalid",
  );
  if (
    commitmentRecord.protocol !== COMMITMENT_PROTOCOL ||
    commitmentRecord.version !== CURRENT_PROTOCOL_VERSION ||
    commitmentRecord.ake_suite_id !== SUITE_IDS.INITIAL_AKE ||
    commitmentRecord.ake_suite_rank !== CURRENT_SUITE_RANK ||
    commitmentRecord.initial_delivery_suite_id !== SUITE_IDS.INITIAL_DELIVERY ||
    commitmentRecord.initial_delivery_suite_rank !== CURRENT_SUITE_RANK ||
    commitmentRecord.purpose !== purpose
  ) {
    throw new Error("initiator_ake_commitment_policy_invalid");
  }
  const commitmentTranscript = buildInitiatorAkeCommitmentTranscript({
    ownerDeviceId: stringField(commitmentInitiator.device_id, "initiator_device_invalid"),
    commitmentPayload: commitment,
    initiator: commitmentInitiator as StrictJsonValue,
    akeInputs: commitmentAkeInputs as StrictJsonValue,
    binding: {
      operation_id: stringField(commitmentRecord.operation_id, "commitment_operation_invalid"),
      context_hash: stringField(commitmentRecord.context_hash, "commitment_context_invalid"),
      directory_hash: stringField(commitmentRecord.directory_hash, "commitment_directory_invalid"),
      recipient_hash: stringField(commitmentRecord.recipient_hash, "commitment_recipient_invalid"),
      server_challenge: stringField(
        commitmentRecord.server_challenge,
        "commitment_challenge_invalid",
      ),
    },
  });
  if (
    !verifyInitiatorAkeCommitmentSignature({
      publicKeyMaterial: params.senderSigningPublicKeyMaterial,
      signature: params.initialAke.initiator_commitment_signature,
      transcript: commitmentTranscript,
    })
  ) {
    throw new Error("initiator_ake_commitment_signature_invalid");
  }
  const commitmentHash = blake3Base64Url(canonicalizeStrictBytes(commitment));
  const delivery = params.initialKeyDelivery;
  const metadata = assertRecord(delivery.metadata, "initial_delivery_metadata_invalid");
  if (
    initiator.initiator_commitment_hash !== commitmentHash ||
    commitmentAkeInputs.x25519_ephemeral_public !== initiator.x25519_ephemeral_public ||
    commitmentAkeInputs.mlkem768_enc !== initiator.mlkem768_enc ||
    commitmentRecord.operation_id !== contextRecord.operation_id ||
    commitmentRecord.context_hash !==
      blake3Base64Url(canonicalizeStrictBytes(contextRecord as StrictJsonValue)) ||
    commitmentRecord.directory_hash !==
      blake3Base64Url(canonicalizeStrictBytes(transcript.directory as StrictJsonValue)) ||
    commitmentRecord.recipient_hash !==
      blake3Base64Url(
        canonicalizeStrictBytes({
          user_id: stringField(responder.user_id, "responder_user_invalid"),
          device_id: stringField(responder.device_id, "responder_device_invalid"),
          encryption_key_id: stringField(
            metadata.recipient_encryption_key_id,
            "initial_delivery_recipient_invalid",
          ),
          prekey_hash: stringField(responder.prekey_hash, "responder_prekey_hash_invalid"),
        }),
      ) ||
    commitmentRecord.server_challenge !== contextRecord.challenge ||
    commitmentAkeInputs.responder_prekey_hash !== responder.prekey_hash
  ) {
    throw new Error("initiator_ake_commitment_binding_invalid");
  }
  const dh = x25519.getSharedSecret(
    decodeBase64UrlStrict(params.privatePrekey.x25519_private, X25519_PRIVATE_BYTES),
    decodeBase64UrlStrict(
      stringField(initiator.x25519_ephemeral_public, "initiator_x25519_invalid"),
      X25519_PUBLIC_BYTES,
    ),
  );
  assertNonZeroSharedSecret(dh);
  const kem = ml_kem768.decapsulate(
    decodeBase64UrlStrict(
      stringField(initiator.mlkem768_enc, "initiator_mlkem_invalid"),
      MLKEM_CIPHERTEXT_BYTES,
    ),
    decodeBase64UrlStrict(params.privatePrekey.mlkem768_private, MLKEM_PRIVATE_BYTES),
  );
  const secret = deriveAkeSecret(dh, kem, transcriptHashBytes, purpose);
  const expectedInitiatorConfirmation = hmac(
    sha256,
    secret,
    concatBytes(new TextEncoder().encode("initiator-confirm"), transcriptHashBytes),
  );
  const expectedResponderConfirmation = hmac(
    sha256,
    secret,
    concatBytes(new TextEncoder().encode("responder-confirm"), transcriptHashBytes),
  );
  if (
    !constantTimeEqual(
      expectedInitiatorConfirmation,
      decodeBase64UrlStrict(params.initialAke.initiator_confirmation, 32),
    ) ||
    !constantTimeEqual(
      expectedResponderConfirmation,
      decodeBase64UrlStrict(params.initialAke.responder_confirmation, 32),
    )
  ) {
    throw new Error("initial_ake_key_confirmation_invalid");
  }
  const expectedKeyConfirmationHash = blake3Base64Url(
    concatBytes(expectedInitiatorConfirmation, expectedResponderConfirmation),
  );
  const aead = assertRecord(delivery.aead, "initial_delivery_aead_invalid");
  const authority = assertRecord(delivery.authority, "initial_delivery_authority_invalid");
  assertExactKeys(deliveryRecord, INITIAL_KEY_DELIVERY_KEYS, "initial_delivery_payload_invalid");
  assertExactKeys(aead, INITIAL_DELIVERY_AEAD_KEYS, "initial_delivery_aead_invalid");
  assertExactKeys(authority, INITIAL_DELIVERY_AUTHORITY_KEYS, "initial_delivery_authority_invalid");
  if (authority.sender_authority_kind !== "device") {
    throw new Error("initial_delivery_authority_invalid");
  }
  assertInitialDeliveryMetadataKeys(purpose, metadata);
  if (
    delivery.initial_delivery_suite_id !== SUITE_IDS.INITIAL_DELIVERY ||
    delivery.initial_delivery_suite_rank !== CURRENT_SUITE_RANK ||
    metadata.suite_id !== SUITE_IDS.INITIAL_DELIVERY ||
    metadata.suite_rank !== CURRENT_SUITE_RANK ||
    aead.suite_id !== SUITE_IDS.INITIAL_DELIVERY ||
    aead.suite_rank !== CURRENT_SUITE_RANK
  ) {
    throw new Error("initial_delivery_suite_not_allowed");
  }
  const payloadKind = stringField(metadata.payload_kind, "payload_kind_invalid");
  if (metadata.ake_transcript_hash !== transcriptHash) {
    throw new Error("initial_delivery_ake_hash_mismatch");
  }
  if (metadata.key_confirmation_hash !== expectedKeyConfirmationHash) {
    throw new Error("initial_delivery_key_confirmation_hash_mismatch");
  }
  const signingBody = { ...delivery };
  delete (signingBody as Record<string, unknown>).signature;
  const senderDeviceId = stringField(metadata.sender_device_id, "initial_delivery_sender_invalid");
  const signatureTranscript = buildInitialKeyDeliveryTranscript({
    ownerDeviceId: senderDeviceId,
    variant: purpose,
    deliverySigningBody: signingBody as unknown as StrictJsonValue,
    sender: {
      user_id: assertRecord(transcript.context, "initial_ake_context_invalid")
        .owner_user_id as string,
      device_id: senderDeviceId,
      signing_key_id: params.initialKeyDelivery.signature.signing_key_id,
    },
    recipient: {
      user_id: assertRecord(transcript.context, "initial_ake_context_invalid")
        .owner_user_id as string,
      device_id: stringField(metadata.recipient_device_id, "initial_delivery_recipient_invalid"),
      encryption_key_id: stringField(
        metadata.recipient_encryption_key_id,
        "initial_delivery_recipient_invalid",
      ),
    },
    ake: {
      ake_transcript_hash: transcriptHash,
      initiator_commitment_hash: stringField(
        metadata.initiator_commitment_hash,
        "commitment_hash_invalid",
      ),
      purpose,
      operation_id: params.privatePrekey.operation_id,
    },
    delivery: {
      delivery_id: stringField(metadata.delivery_id, "delivery_id_invalid"),
      context_hash: stringField(metadata.context_hash, "context_hash_invalid"),
      payload_kind: payloadKind,
      ciphertext_hash: stringField(aead.ciphertext_hash, "ciphertext_hash_invalid"),
    },
    authority: authority as unknown as StrictJsonValue,
  });
  if (
    !verifyInitialKeyDeliverySignature({
      publicKeyMaterial: params.senderSigningPublicKeyMaterial,
      signature: delivery.signature,
      transcript: signatureTranscript,
    })
  ) {
    throw new Error("initial_key_delivery_signature_invalid");
  }
  const ciphertext = decodeBase64UrlStrict(stringField(aead.ciphertext, "ciphertext_invalid"));
  if (
    stringField(aead.ciphertext_hash, "ciphertext_hash_invalid") !== blake3Base64Url(ciphertext)
  ) {
    throw new Error("ciphertext_hash_mismatch");
  }
  const deliveryKey = deriveDeliveryKey(
    secret,
    transcriptHashBytes,
    stringField(metadata.context_hash, "context_hash_invalid"),
    purpose,
  );
  const aadBytes = initialDeliveryAad({
    purpose,
    deliveryId: stringField(metadata.delivery_id, "delivery_id_invalid"),
    transcriptHash,
    contextHash: stringField(metadata.context_hash, "context_hash_invalid"),
    commitmentHash: stringField(metadata.initiator_commitment_hash, "commitment_hash_invalid"),
    senderHash: blake3Base64Url(
      canonicalizeStrictBytes({
        user_id: assertRecord(transcript.context, "initial_ake_context_invalid")
          .owner_user_id as string,
        device_id: senderDeviceId,
      }),
    ),
    recipientHash: stringField(commitmentRecord.recipient_hash, "recipient_hash_invalid"),
    payloadMetadataHash: blake3Base64Url(
      canonicalizeStrictBytes(metadata as unknown as StrictJsonValue),
    ),
  });
  return xchacha20poly1305(
    deliveryKey,
    decodeBase64UrlStrict(stringField(aead.nonce, "nonce_invalid"), 24),
    aadBytes,
  ).decrypt(ciphertext);
}

export function encodeInitialAkeJson(value: unknown): string {
  return new TextDecoder().decode(canonicalizeStrictBytes(value as StrictJsonValue));
}

export function decodeInitialAkeRecord<T>(value: unknown): T {
  if (typeof value === "string") return parseJsonStrictBytes(new TextEncoder().encode(value)) as T;
  return parseJsonStrictBytes(canonicalizeStrictBytes(value as StrictJsonValue)) as T;
}

function assertExactKeys(
  value: Record<string, unknown>,
  expectedKeys: readonly string[],
  error: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length) throw new Error(error);
  for (let i = 0; i < actual.length; i += 1) {
    if (actual[i] !== expected[i]) throw new Error(error);
  }
}

function assertInitialDeliveryMetadataKeys(
  purpose: InitialAkePurpose,
  metadata: Record<string, unknown>,
): void {
  const purposeKeys =
    purpose === "trust_transfer"
      ? [...INITIAL_DELIVERY_COMMON_METADATA_KEYS, "document_rollback_pin_set_hash"]
      : purpose === "device_approval_kek_initial"
        ? [...INITIAL_DELIVERY_COMMON_METADATA_KEYS, "workspace_id"]
        : INITIAL_DELIVERY_COMMON_METADATA_KEYS;
  assertExactKeys(metadata, purposeKeys, "initial_delivery_metadata_invalid");
}

function assertInitialAkeContextKeys(
  purpose: InitialAkePurpose,
  context: Record<string, unknown>,
): void {
  const keys =
    purpose === "trust_transfer"
      ? INITIAL_AKE_TRUST_CONTEXT_KEYS
      : purpose === "device_approval_kek_initial"
        ? INITIAL_AKE_APPROVAL_CONTEXT_KEYS
        : INITIAL_AKE_UMK_CONTEXT_KEYS;
  assertExactKeys(context, keys, "initial_ake_context_invalid");
}

function assertInitialAkeDirectoryKeys(
  purpose: InitialAkePurpose,
  directory: Record<string, unknown>,
): void {
  const keys =
    purpose === "trust_transfer"
      ? INITIAL_AKE_TRUST_DIRECTORY_KEYS
      : purpose === "device_approval_kek_initial"
        ? INITIAL_AKE_APPROVAL_DIRECTORY_KEYS
        : INITIAL_AKE_UMK_DIRECTORY_KEYS;
  assertExactKeys(directory, keys, "initial_ake_directory_invalid");
}
