import {
  getKeyDirectoryPin,
  hasVerifiedKeyDirectoryEvent,
  hydrateVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { checkpointHash, eventHash } from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";

export interface RecipientDeliveryAttemptBinding {
  context_id: string;
  context_kind: "workspace_invitation" | "guest_invitation";
  context_snapshot: Record<string, unknown>;
  live_redeem_challenge_hash: string;
  recipient_nonce_state_hash: string;
  recipient_redeem_nonce: string;
  redeem_attempt_id: string;
  resource_hash: string;
  target_device_id: string;
  target_encryption_key_id: string;
  target_user_id: string;
  workspace_id: string;
}

export interface RecipientDeliveryAdmissionProof {
  attempt: RecipientDeliveryAttemptBinding;
  authorization: Record<string, unknown>;
  freshnessProof: Record<string, unknown>;
  baseCheckpoint: SignedKeyDirectoryEnvelope;
  currentCheckpoint: SignedKeyDirectoryEnvelope;
  authorityEventAncestry: SignedKeyDirectoryEnvelope[];
  acceptedEventAncestry: SignedKeyDirectoryEnvelope[];
}

const ADMISSION_BODY_KEYS = [
  "admission_nonce",
  "authorization_hash",
  "authorization_id",
  "context_id",
  "context_kind",
  "event_type",
  "live_redeem_challenge_hash",
  "permission",
  "previous_workspace_event_hash",
  "previous_workspace_event_sequence",
  "recipient_device_id",
  "recipient_hash",
  "recipient_nonce_state_hash",
  "redeem_attempt_id",
  "redeem_freshness_proof_hash",
  "share_session_binding_hash",
  "share_session_id",
  "workspace_id",
] as const;

const verifiedAdmission = Symbol("verified-recipient-delivery-admission");

export interface VerifiedRecipientDeliveryAdmission {
  readonly [verifiedAdmission]: true;
  readonly event: SignedKeyDirectoryEnvelope;
}

export function recipientDeliveryOperationProof<T extends Record<string, unknown>>(
  admission: VerifiedRecipientDeliveryAdmission,
  operationProof: T,
): T {
  if (admission[verifiedAdmission] !== true) {
    throw new Error("recipient_delivery_admission_required");
  }
  return operationProof;
}

export async function verifyRecipientDeliveryAdmission(
  params: RecipientDeliveryAdmissionProof,
): Promise<VerifiedRecipientDeliveryAdmission> {
  const event = assertRecipientDeliveryAdmissionBindings(params);
  const sequence = positiveInteger(event.payload.sequence, "recipient_delivery_sequence_invalid");
  const hash = eventHash(event);
  const pin = await getKeyDirectoryPin("workspace", params.attempt.workspace_id);
  const currentPayload = params.currentCheckpoint.payload;
  const currentHead = recordField(
    currentPayload.covered_event_head,
    "recipient_delivery_checkpoint_head_invalid",
  );

  if (pin) {
    await hydrateVerifiedKeyDirectoryLineage("workspace", params.attempt.workspace_id, pin);
  }

  if (
    !pin ||
    pin.checkpointSequence !== currentPayload.sequence ||
    pin.checkpointHash !== checkpointHash(params.currentCheckpoint) ||
    pin.eventHeadSequence !== currentHead.head_sequence ||
    pin.eventHeadHash !== currentHead.head_hash ||
    sequence > pin.eventHeadSequence ||
    !hasVerifiedKeyDirectoryEvent("workspace", params.attempt.workspace_id, sequence, hash)
  ) {
    throw new Error("recipient_delivery_admission_not_in_pinned_chain");
  }

  return { [verifiedAdmission]: true, event };
}

export function assertRecipientDeliveryAdmissionBindings(
  params: RecipientDeliveryAdmissionProof,
): SignedKeyDirectoryEnvelope {
  const { attempt } = params;
  const authorization = recordField(
    params.authorization,
    "recipient_delivery_authorization_invalid",
  );
  const freshnessProof = recordField(
    params.freshnessProof,
    "recipient_delivery_freshness_proof_invalid",
  );
  const authorizationPayload = recordField(
    authorization.payload,
    "recipient_delivery_authorization_payload_invalid",
  );
  const recipient = recordField(
    authorizationPayload.recipient,
    "recipient_delivery_authorization_recipient_invalid",
  );
  const baseHead = recordField(
    params.baseCheckpoint.payload.covered_event_head,
    "recipient_delivery_base_head_invalid",
  );
  const currentHead = recordField(
    params.currentCheckpoint.payload.covered_event_head,
    "recipient_delivery_checkpoint_head_invalid",
  );
  const expectedRecipientKind =
    attempt.context_kind === "workspace_invitation" ? "invitee" : "guest";

  if (
    authorizationPayload.protocol !== "refmd.recipient-bound-authorization" ||
    authorizationPayload.version !== 1 ||
    authorizationPayload.redeem_attempt_id !== attempt.redeem_attempt_id ||
    authorizationPayload.workspace_id !== attempt.workspace_id ||
    authorizationPayload.context_kind !== attempt.context_kind ||
    authorizationPayload.context_id !== attempt.context_id ||
    authorizationPayload.resource_hash !== attempt.resource_hash ||
    authorizationPayload.recipient_redeem_nonce !== attempt.recipient_redeem_nonce ||
    authorizationPayload.recipient_nonce_state_hash !== attempt.recipient_nonce_state_hash ||
    authorizationPayload.live_redeem_challenge_hash !== attempt.live_redeem_challenge_hash ||
    authorizationPayload.redeem_freshness_proof_hash !== hash(freshnessProof) ||
    authorizationPayload.current_checkpoint_sequence !== params.baseCheckpoint.payload.sequence ||
    authorizationPayload.current_checkpoint_hash !== checkpointHash(params.baseCheckpoint) ||
    authorizationPayload.current_event_head_sequence !== baseHead.head_sequence ||
    authorizationPayload.current_event_head_hash !== baseHead.head_hash ||
    authorizationPayload.not_after_event_sequence !==
      positiveInteger(baseHead.head_sequence, "recipient_delivery_base_sequence_invalid") + 1 ||
    recipient.recipient_kind !== expectedRecipientKind ||
    recipient.recipient_principal_id !== attempt.target_user_id ||
    recipient.recipient_device_id !== attempt.target_device_id ||
    recipient.encryption_key_id !== attempt.target_encryption_key_id
  ) {
    throw new Error("recipient_delivery_authorization_binding_mismatch");
  }

  const allEvents = uniqueEvents([
    ...params.authorityEventAncestry,
    ...params.acceptedEventAncestry,
  ]);
  const admissions = allEvents.filter((event) => {
    const body = event.payload.body as Record<string, unknown> | undefined;
    return (
      event.payload.event_type === "recipient_bound_delivery_admitted" &&
      (body?.redeem_attempt_id === attempt.redeem_attempt_id ||
        body?.authorization_id === authorizationPayload.authorization_id)
    );
  });
  if (admissions.length !== 1) {
    throw new Error("recipient_delivery_admission_count_invalid");
  }
  const admission = admissions[0]!;
  const body = recordField(admission.payload.body, "recipient_delivery_admission_body_invalid");
  const admissionSequence = positiveInteger(
    admission.payload.sequence,
    "recipient_delivery_sequence_invalid",
  );
  const expectedSequence =
    positiveInteger(baseHead.head_sequence, "recipient_delivery_base_sequence_invalid") + 1;

  if (
    Object.keys(body).sort().join("\u0000") !== [...ADMISSION_BODY_KEYS].sort().join("\u0000") ||
    admission.payload.scope_kind !== "workspace" ||
    admission.payload.scope_id !== attempt.workspace_id ||
    admissionSequence !== expectedSequence ||
    admission.payload.previous_event_hash !== baseHead.head_hash ||
    body.event_type !== "recipient_bound_delivery_admitted" ||
    body.authorization_id !== authorizationPayload.authorization_id ||
    body.redeem_attempt_id !== attempt.redeem_attempt_id ||
    body.authorization_hash !== hash(authorizationPayload) ||
    body.workspace_id !== attempt.workspace_id ||
    body.context_kind !== attempt.context_kind ||
    body.context_id !== attempt.context_id ||
    body.recipient_hash !== hash(recipient) ||
    body.recipient_device_id !== attempt.target_device_id ||
    body.permission !== "NOT_APPLICABLE" ||
    body.share_session_id !== "NOT_APPLICABLE" ||
    body.share_session_binding_hash !== "NOT_APPLICABLE" ||
    body.recipient_nonce_state_hash !== attempt.recipient_nonce_state_hash ||
    body.live_redeem_challenge_hash !== attempt.live_redeem_challenge_hash ||
    body.redeem_freshness_proof_hash !== hash(freshnessProof) ||
    body.previous_workspace_event_sequence !== baseHead.head_sequence ||
    body.previous_workspace_event_hash !== baseHead.head_hash ||
    !isBase64Url32(body.admission_nonce)
  ) {
    throw new Error("recipient_delivery_admission_binding_mismatch");
  }

  assertInvitationActiveAtAdmission(allEvents, attempt, admissionSequence);
  assertExpectedRedeemAndNoLaterInvalidation(allEvents, attempt, admissionSequence);
  const acceptedLast = params.acceptedEventAncestry.at(-1);
  if (
    !acceptedLast ||
    currentHead.head_sequence !== acceptedLast.payload.sequence ||
    currentHead.head_hash !== eventHash(acceptedLast) ||
    admissionSequence >
      positiveInteger(currentHead.head_sequence, "recipient_delivery_head_invalid")
  ) {
    throw new Error("recipient_delivery_admission_not_ancestor");
  }
  return admission;
}

function assertInvitationActiveAtAdmission(
  events: SignedKeyDirectoryEnvelope[],
  attempt: RecipientDeliveryAttemptBinding,
  admissionSequence: number,
): void {
  let active = false;
  let expiresAt: number | null = null;
  for (const event of events) {
    const sequence = positiveInteger(event.payload.sequence, "recipient_delivery_event_invalid");
    if (sequence >= admissionSequence) break;
    const body = event.payload.body as Record<string, unknown> | undefined;
    if (!body) continue;
    const invitationId =
      attempt.context_kind === "workspace_invitation"
        ? body.invitation_id
        : body.guest_invitation_id;
    if (invitationId !== attempt.context_id) continue;
    if (event.payload.event_type === `${attempt.context_kind}_created`) {
      active = true;
      expiresAt = positiveInteger(
        body.expires_event_sequence,
        "recipient_delivery_invitation_expiry_invalid",
      );
    }
    if (
      event.payload.event_type === `${attempt.context_kind}_revoked` ||
      event.payload.event_type === `${attempt.context_kind}_redeemed`
    ) {
      active = false;
    }
  }
  if (!active || expiresAt === null || admissionSequence >= expiresAt) {
    throw new Error("recipient_delivery_invitation_inactive");
  }
}

function assertExpectedRedeemAndNoLaterInvalidation(
  events: SignedKeyDirectoryEnvelope[],
  attempt: RecipientDeliveryAttemptBinding,
  admissionSequence: number,
): void {
  const expectedRedeemType = `${attempt.context_kind}_redeemed`;
  const invitationIdField =
    attempt.context_kind === "workspace_invitation" ? "invitation_id" : "guest_invitation_id";
  const matchingAfterAdmission = events.filter((event) => {
    const sequence = positiveInteger(event.payload.sequence, "recipient_delivery_event_invalid");
    const body = event.payload.body as Record<string, unknown> | undefined;
    return sequence > admissionSequence && body?.[invitationIdField] === attempt.context_id;
  });
  const redeems = matchingAfterAdmission.filter(
    (event) => event.payload.event_type === expectedRedeemType,
  );
  if (redeems.length !== 1) throw new Error("recipient_delivery_redeem_event_invalid");
  if (
    matchingAfterAdmission.some(
      (event) =>
        event.payload.event_type === `${attempt.context_kind}_revoked` ||
        (event.payload.event_type === expectedRedeemType && event !== redeems[0]),
    )
  ) {
    throw new Error("recipient_delivery_post_admission_invalidated");
  }
}

function uniqueEvents(events: SignedKeyDirectoryEnvelope[]): SignedKeyDirectoryEnvelope[] {
  return [...new Map(events.map((event) => [eventHash(event), event])).values()].sort(
    (left, right) => Number(left.payload.sequence) - Number(right.payload.sequence),
  );
}

function recordField(value: unknown, error: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(error);
  return value as Record<string, unknown>;
}

function positiveInteger(value: unknown, error: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) throw new Error(error);
  return value;
}

function isBase64Url32(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    return base64UrlDecode(value).length === 32;
  } catch {
    return false;
  }
}

function hash(value: unknown): string {
  return blake3Base64Url(canonicalizeStrictBytes(value as StrictJsonValue));
}
