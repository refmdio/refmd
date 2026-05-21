import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { getActiveSigningSurface } from "./signing-surface";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";
import { KEY_DIRECTORY_EVENT_VARIANTS } from "./signature-transcript-schemas";
import { transcriptBase, type SigningOwnerKind } from "./signature-transcript-core";

export function buildKeyDirectoryCheckpointTranscript(params: {
  variant:
    | "identity_initial"
    | "workspace_initial"
    | "identity_active"
    | "identity_rotation"
    | "workspace_authorized"
    | "invitation_redeem_authority"
    | "share_participant_document_operation"
    | "device_authorized";
  ownerKind: SigningOwnerKind;
  ownerId: string;
  checkpointPayload: StrictJsonValue;
  signer: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("key_directory_checkpoint", params.variant);
  const subject = canonicalizeStrictBytes(params.checkpointPayload);
  const checkpoint = params.checkpointPayload as Record<string, unknown>;
  const coveredHead = checkpoint.covered_event_head as Record<string, unknown>;
  const sequence = checkpoint.sequence as number;
  const signer = requiredRecord(params.signer) as Record<string, unknown>;

  return transcriptBase("key_directory_checkpoint", surface, params.ownerKind, params.ownerId, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.key-directory-checkpoint",
    subject_version: CURRENT_PROTOCOL_VERSION,
    scope: {
      scope_kind: checkpoint.scope_kind as string,
      scope_id: checkpoint.scope_id as string,
      checkpoint_sequence: sequence,
      ...(sequence === 1
        ? {}
        : { previous_checkpoint_hash: requiredString(checkpoint.previous_checkpoint_hash) }),
      covered_event_head_sequence: coveredHead.head_sequence as number,
      covered_event_head_hash: coveredHead.head_hash as string,
    },
    signer,
    authority_boundary: keyDirectoryCheckpointAuthorityBoundary(sequence, signer),
    suite_policy: {
      suite_policy_version: checkpoint.suite_policy_version as number,
      min_suite_rank: checkpoint.min_suite_rank as number,
      allowed_suite_ids_hash: blake3Base64Url(
        canonicalizeStrictBytes({
          allowed_suite_ids: checkpoint.allowed_suite_ids as StrictJsonValue,
        }),
      ),
    },
  });
}

export function buildPqWrapTranscript(params: {
  ownerDeviceId: string;
  actor: StrictJsonValue;
  authorityBoundary: StrictJsonValue;
  subjectHashes: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("pq_wrap", "none");
  return transcriptBase("pq_wrap", surface, "device", params.ownerDeviceId, {
    subject_protocol: "refmd.signed-pq-hybrid-wrap",
    subject_version: CURRENT_PROTOCOL_VERSION,
    subject_suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    subject_suite_rank: CURRENT_SUITE_RANK,
    actor: params.actor,
    authority_boundary: params.authorityBoundary,
    subject_hashes: params.subjectHashes,
  });
}

export function buildKeyDirectoryEventTranscript(params: {
  eventType: (typeof KEY_DIRECTORY_EVENT_VARIANTS)[number];
  ownerKind: SigningOwnerKind;
  ownerId: string;
  eventPayload: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("key_directory_event", params.eventType);
  const subject = canonicalizeStrictBytes(params.eventPayload);
  const event = params.eventPayload as Record<string, unknown>;
  const sequence = event.sequence as number;

  return transcriptBase("key_directory_event", surface, params.ownerKind, params.ownerId, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.key-directory-event",
    subject_version: CURRENT_PROTOCOL_VERSION,
    event: {
      event_body_hash: blake3Base64Url(canonicalizeStrictBytes(event.body as StrictJsonValue)),
      event_type: event.event_type as string,
      ...(sequence === 1 ? {} : { previous_event_hash: requiredString(event.previous_event_hash) }),
      scope_id: event.scope_id as string,
      scope_kind: event.scope_kind as string,
      sequence,
    },
    actor: requiredRecord(event.actor),
    authority_boundary: keyDirectoryEventAuthorityBoundary(event),
  });
}

function keyDirectoryCheckpointAuthorityBoundary(
  sequence: number,
  signer: Record<string, unknown>,
): StrictJsonValue {
  if (sequence === 1) {
    return { required_authority: "tofu_root" };
  }
  if (signer.signer_kind === "invitation_redeem_authority") {
    return {
      required_authority: "invitation_redeem_authority",
      invitation_id: requiredString(signer.invitation_id),
    };
  }
  return {
    required_authority: "checkpoint_authorized",
    authorizing_checkpoint_sequence: numberValue(
      signer.authorizing_checkpoint_sequence,
      "authorizing_checkpoint_sequence",
    ),
    authorizing_checkpoint_hash: requiredString(signer.authorizing_checkpoint_hash),
  };
}

function keyDirectoryEventAuthorityBoundary(event: Record<string, unknown>): StrictJsonValue {
  const actor = requiredRecord(event.actor) as Record<string, unknown>;
  const scopeKind = requiredString(event.scope_kind);
  const scopeId = requiredString(event.scope_id);
  const sequence = numberValue(event.sequence, "sequence");

  if ("key_checkpoint_sequence" in actor && "key_checkpoint_hash" in actor) {
    return {
      scope_kind: scopeKind,
      scope_id: scopeId,
      checkpoint_sequence: numberValue(actor.key_checkpoint_sequence, "key_checkpoint_sequence"),
      checkpoint_hash: requiredString(actor.key_checkpoint_hash),
      required_authority: "event_type_authorized_actor",
    };
  }

  if (actor.signer_kind === "invitation_redeem_authority") {
    return {
      required_authority: "invitation_redeem_authority",
      invitation_id: requiredString(actor.invitation_id),
      event_type: requiredString(event.event_type),
    };
  }

  if (sequence === 1) return { required_authority: "tofu_root" };
  throw new Error("key_directory_event_authority_boundary_invalid");
}

function requiredRecord(value: unknown): StrictJsonValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("key_directory_transcript_required_record_missing");
  }
  return value as StrictJsonValue;
}

function numberValue(value: unknown, field: string): number {
  if (!Number.isInteger(value)) {
    throw new Error(`key_directory_transcript_${field}_invalid`);
  }
  return value as number;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("key_directory_transcript_required_field_missing");
  }
  return value;
}

function requiredBootstrapString(value: StrictJsonValue, key: string): string {
  const record = requiredRecord(value) as Record<string, unknown>;
  return requiredString(record[key]);
}

function requiredNumber(value: StrictJsonValue, key: string): number {
  const record = requiredRecord(value) as Record<string, unknown>;
  const field = record[key];
  if (typeof field !== "number" || !Number.isSafeInteger(field) || field < 1) {
    throw new Error("key_directory_transcript_required_field_missing");
  }
  return field;
}

export function buildWorkspacePinBootstrapTranscript(params: {
  ownerDeviceId: string;
  workspaceId: string;
  bootstrap: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("workspace_pin_bootstrap", "none");
  const subject = canonicalizeStrictBytes(params.bootstrap);

  return transcriptBase("workspace_pin_bootstrap", surface, "device", params.ownerDeviceId, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.workspace-pin-bootstrap",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor: requiredRecord((params.bootstrap as Record<string, unknown>).issuer),
    authority_boundary: {
      scope_kind: "workspace",
      scope_id: params.workspaceId,
      checkpoint_sequence: requiredNumber(params.bootstrap, "checkpoint_sequence"),
      checkpoint_hash: requiredBootstrapString(params.bootstrap, "checkpoint_hash"),
      event_head_sequence: requiredNumber(params.bootstrap, "event_head_sequence"),
      event_head_hash: requiredBootstrapString(params.bootstrap, "event_head_hash"),
      issuing_event_hash: requiredBootstrapString(params.bootstrap, "issuing_event_hash"),
    },
    suite_policy: {
      suite_policy_version: requiredNumber(params.bootstrap, "suite_policy_version"),
      min_suite_rank: requiredNumber(params.bootstrap, "min_suite_rank"),
      allowed_suite_ids_hash: requiredBootstrapString(params.bootstrap, "allowed_suite_ids_hash"),
    },
  });
}

export function buildPinGossipStatementTranscript(params: {
  ownerDeviceId: string;
  pinGossip: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("pin_gossip_statement", "none");
  const subject = canonicalizeStrictBytes(params.pinGossip);

  return transcriptBase("pin_gossip_statement", surface, "device", params.ownerDeviceId, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.pin.gossip_statement",
    subject_version: CURRENT_PROTOCOL_VERSION,
    pin_gossip: {
      statement_hash: blake3Base64Url(subject),
      statement: params.pinGossip,
    },
  });
}

export function buildRecipientBoundAuthorizationTranscript(params: {
  ownerId: string;
  actorUserId: string;
  actorDeviceId: string;
  signingKeyId: string;
  authorizationPayload: Record<string, unknown>;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("recipient_bound_authorization", "none");
  const payload = normalizeRecipientBoundAuthorizationPayload(params.authorizationPayload);
  if (payload.redeem_authority_signing_key_id !== params.signingKeyId) {
    throw new Error("recipient_bound_authorization_signing_key_mismatch");
  }
  const recipient = requiredRecord(payload.recipient) as Record<string, unknown>;
  const subject = canonicalizeStrictBytes(payload as unknown as StrictJsonValue);

  return transcriptBase("recipient_bound_authorization", surface, "device", params.ownerId, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.recipient-bound-authorization",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor: {
      signer_kind: "device",
      user_id: params.actorUserId,
      device_id: params.actorDeviceId,
      signing_key_id: params.signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: payload.workspace_id,
      key_checkpoint_sequence: payload.current_checkpoint_sequence,
      key_checkpoint_hash: payload.current_checkpoint_hash,
    },
    authority_boundary: {
      workspace_id: payload.workspace_id,
      authorization_id: payload.authorization_id,
      redeem_attempt_id: payload.redeem_attempt_id,
      context_kind: payload.context_kind,
      context_id: payload.context_id,
      current_checkpoint_sequence: payload.current_checkpoint_sequence,
      current_checkpoint_hash: payload.current_checkpoint_hash,
      current_event_head_sequence: payload.current_event_head_sequence,
      current_event_head_hash: payload.current_event_head_hash,
      resource_hash: payload.resource_hash,
      workspace_pin_bootstrap_hash: payload.workspace_pin_bootstrap_hash,
    },
    recipient,
    freshness: {
      recipient_redeem_nonce: payload.recipient_redeem_nonce,
      recipient_nonce_state_hash: payload.recipient_nonce_state_hash,
      live_redeem_challenge_hash: payload.live_redeem_challenge_hash,
      redeem_freshness_proof_hash: payload.redeem_freshness_proof_hash,
      not_after_event_sequence: payload.not_after_event_sequence,
    },
  });
}

function normalizeRecipientBoundAuthorizationPayload(payload: Record<string, unknown>): {
  authorization_id: string;
  redeem_attempt_id: string;
  workspace_id: string;
  context_kind: "workspace_invitation" | "guest_invitation" | "share";
  context_id: string;
  resource_hash: string;
  recipient: StrictJsonValue;
  workspace_pin_bootstrap_hash: string;
  current_checkpoint_sequence: number;
  current_checkpoint_hash: string;
  current_event_head_sequence: number;
  current_event_head_hash: string;
  redeem_authority_signing_key_id: string;
  recipient_redeem_nonce: string;
  recipient_nonce_state_hash: string;
  live_redeem_challenge_hash: string;
  redeem_freshness_proof_hash: string;
  not_after_event_sequence: number;
  protocol: "refmd.recipient-bound-authorization";
  version: 1;
} {
  const keys = Object.keys(payload).sort();
  const expected = [
    "authorization_id",
    "context_id",
    "context_kind",
    "current_checkpoint_hash",
    "current_checkpoint_sequence",
    "current_event_head_hash",
    "current_event_head_sequence",
    "live_redeem_challenge_hash",
    "not_after_event_sequence",
    "protocol",
    "recipient",
    "recipient_nonce_state_hash",
    "recipient_redeem_nonce",
    "redeem_attempt_id",
    "redeem_authority_signing_key_id",
    "redeem_freshness_proof_hash",
    "resource_hash",
    "workspace_id",
    "workspace_pin_bootstrap_hash",
    "version",
  ].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error("recipient_bound_authorization_payload_invalid");
  }
  const recipient = requiredRecord(payload.recipient) as Record<string, unknown>;
  const recipientKeys = Object.keys(recipient).sort();
  const expectedRecipientKeys = [
    "encryption_key_id",
    "recipient_device_id",
    "recipient_kind",
    "recipient_principal_id",
  ];
  if (
    recipientKeys.length !== expectedRecipientKeys.length ||
    recipientKeys.some((key, index) => key !== expectedRecipientKeys[index])
  ) {
    throw new Error("recipient_bound_authorization_recipient_invalid");
  }
  const contextKind = requiredString(payload.context_kind);
  if (
    contextKind !== "workspace_invitation" &&
    contextKind !== "guest_invitation" &&
    contextKind !== "share"
  ) {
    throw new Error("recipient_bound_authorization_context_kind_invalid");
  }
  const recipientKind = requiredString(recipient.recipient_kind);
  if (
    recipientKind !== "invitee" &&
    recipientKind !== "guest" &&
    recipientKind !== "share_participant_device"
  ) {
    throw new Error("recipient_bound_authorization_recipient_kind_invalid");
  }
  if (
    payload.protocol !== "refmd.recipient-bound-authorization" ||
    payload.version !== CURRENT_PROTOCOL_VERSION
  ) {
    throw new Error("recipient_bound_authorization_protocol_invalid");
  }
  return {
    authorization_id: requiredString(payload.authorization_id),
    redeem_attempt_id: requiredString(payload.redeem_attempt_id),
    workspace_id: requiredString(payload.workspace_id),
    context_kind: contextKind,
    context_id: requiredString(payload.context_id),
    resource_hash: requiredString(payload.resource_hash),
    recipient: recipient as StrictJsonValue,
    workspace_pin_bootstrap_hash: requiredString(payload.workspace_pin_bootstrap_hash),
    current_checkpoint_sequence: numberValue(
      payload.current_checkpoint_sequence,
      "current_checkpoint_sequence",
    ),
    current_checkpoint_hash: requiredString(payload.current_checkpoint_hash),
    current_event_head_sequence: numberValue(
      payload.current_event_head_sequence,
      "current_event_head_sequence",
    ),
    current_event_head_hash: requiredString(payload.current_event_head_hash),
    redeem_authority_signing_key_id: requiredString(payload.redeem_authority_signing_key_id),
    recipient_redeem_nonce: requiredString(payload.recipient_redeem_nonce),
    recipient_nonce_state_hash: requiredString(payload.recipient_nonce_state_hash),
    live_redeem_challenge_hash: requiredString(payload.live_redeem_challenge_hash),
    redeem_freshness_proof_hash: requiredString(payload.redeem_freshness_proof_hash),
    not_after_event_sequence: numberValue(
      payload.not_after_event_sequence,
      "not_after_event_sequence",
    ),
    protocol: requiredString(payload.protocol) as "refmd.recipient-bound-authorization",
    version: numberValue(payload.version, "version") as 1,
  };
}

export function buildResponderPrekeyTranscript(params: {
  ownerDeviceId: string;
  prekeyPayload: StrictJsonValue;
  responder: StrictJsonValue;
  freshness: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("responder_prekey", "none");
  return transcriptBase("responder_prekey", surface, "device", params.ownerDeviceId, {
    subject_hash: blake3Base64Url(canonicalizeStrictBytes(params.prekeyPayload)),
    subject_protocol: "refmd.responder-prekey",
    subject_version: CURRENT_PROTOCOL_VERSION,
    responder: params.responder,
    freshness: params.freshness,
  });
}

export function buildInitiatorAkeCommitmentTranscript(params: {
  ownerDeviceId: string;
  commitmentPayload: StrictJsonValue;
  initiator: StrictJsonValue;
  akeInputs: StrictJsonValue;
  binding: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("initiator_ake_commitment", "none");
  return transcriptBase("initiator_ake_commitment", surface, "device", params.ownerDeviceId, {
    subject_hash: blake3Base64Url(canonicalizeStrictBytes(params.commitmentPayload)),
    subject_protocol: "refmd.initiator-ake-commitment",
    subject_version: CURRENT_PROTOCOL_VERSION,
    suite: {
      ake_suite_id: SUITE_IDS.INITIAL_AKE,
      ake_suite_rank: CURRENT_SUITE_RANK,
      initial_delivery_suite_id: SUITE_IDS.INITIAL_DELIVERY,
      initial_delivery_suite_rank: CURRENT_SUITE_RANK,
    },
    initiator: params.initiator,
    ake_inputs: params.akeInputs,
    binding: params.binding,
  });
}

export function buildInitialKeyDeliveryTranscript(params: {
  ownerDeviceId: string;
  variant: "umk_distribution" | "device_approval_kek_initial" | "trust_transfer";
  deliverySigningBody: StrictJsonValue;
  sender: StrictJsonValue;
  recipient: StrictJsonValue;
  ake: StrictJsonValue;
  delivery: StrictJsonValue;
  authority: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("initial_key_delivery", params.variant);
  return transcriptBase("initial_key_delivery", surface, "device", params.ownerDeviceId, {
    subject_hash: blake3Base64Url(canonicalizeStrictBytes(params.deliverySigningBody)),
    subject_protocol: "refmd.initial-key-delivery",
    subject_version: CURRENT_PROTOCOL_VERSION,
    suite: {
      ake_suite_id: SUITE_IDS.INITIAL_AKE,
      ake_suite_rank: CURRENT_SUITE_RANK,
      initial_delivery_suite_id: SUITE_IDS.INITIAL_DELIVERY,
      initial_delivery_suite_rank: CURRENT_SUITE_RANK,
    },
    sender: params.sender,
    recipient: params.recipient,
    ake: params.ake,
    delivery: params.delivery,
    authority: params.authority,
  });
}
