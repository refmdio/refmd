import { checkpointHash, eventHash } from "./primitives";
import type { SignedKeyDirectoryEnvelope } from "./types";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { RecipientDeliveryAdmissionProof } from "./recipient-delivery-admission";

const workspaceId = "11111111-1111-4111-8111-111111111111";
const invitationId = "22222222-2222-4222-8222-222222222222";
const attemptId = "33333333-3333-4333-8333-333333333333";
const targetUserId = "44444444-4444-4444-8444-444444444444";
const targetDeviceId = "55555555-5555-4555-8555-555555555555";
const authorizationId = "66666666-6666-4666-8666-666666666666";
const headHash = hash({ event: "created" });
const nonceHash = hash({ nonce: "state" });
const challengeHash = hash({ challenge: "live" });
const resourceHash = hash({ resource: invitationId });
const encryptionKeyId = hash({ key: targetDeviceId });

export function recipientDeliveryAdmissionFixture(
  kind: "workspace_invitation" | "guest_invitation",
): RecipientDeliveryAdmissionProof {
  const attempt = {
    context_id: invitationId,
    context_kind: kind,
    context_snapshot: {},
    live_redeem_challenge_hash: challengeHash,
    recipient_nonce_state_hash: nonceHash,
    recipient_redeem_nonce: "recipient-redeem-nonce",
    redeem_attempt_id: attemptId,
    resource_hash: resourceHash,
    target_device_id: targetDeviceId,
    target_encryption_key_id: encryptionKeyId,
    target_user_id: targetUserId,
    workspace_id: workspaceId,
  };
  const invitationIdField =
    kind === "workspace_invitation" ? "invitation_id" : "guest_invitation_id";
  const created = envelope({
    scope_kind: "workspace",
    scope_id: workspaceId,
    sequence: 7,
    event_type: `${kind}_created`,
    previous_event_hash: hash({ event: "before-created" }),
    body: {
      workspace_id: workspaceId,
      [invitationIdField]: invitationId,
      expires_event_sequence: 20,
    },
  });
  const baseCheckpoint = checkpoint(4, 7, headHash);
  const freshnessProof = { proof: "fresh" };
  const recipient = {
    recipient_kind: kind === "workspace_invitation" ? "invitee" : "guest",
    recipient_principal_id: targetUserId,
    recipient_device_id: targetDeviceId,
    encryption_key_id: encryptionKeyId,
  };
  const authorizationPayload = {
    protocol: "refmd.recipient-bound-authorization",
    version: 1,
    authorization_id: authorizationId,
    redeem_attempt_id: attemptId,
    workspace_id: workspaceId,
    context_kind: kind,
    context_id: invitationId,
    resource_hash: resourceHash,
    recipient,
    workspace_pin_bootstrap_hash: hash({ bootstrap: workspaceId }),
    current_checkpoint_sequence: 4,
    current_checkpoint_hash: checkpointHash(baseCheckpoint),
    current_event_head_sequence: 7,
    current_event_head_hash: headHash,
    redeem_authority_signing_key_id: hash({ signer: workspaceId }),
    recipient_redeem_nonce: attempt.recipient_redeem_nonce,
    recipient_nonce_state_hash: nonceHash,
    live_redeem_challenge_hash: challengeHash,
    redeem_freshness_proof_hash: hash(freshnessProof),
    not_after_event_sequence: 8,
  };
  const admission = envelope({
    scope_kind: "workspace",
    scope_id: workspaceId,
    sequence: 8,
    event_type: "recipient_bound_delivery_admitted",
    previous_event_hash: headHash,
    body: {
      event_type: "recipient_bound_delivery_admitted",
      authorization_id: authorizationId,
      redeem_attempt_id: attemptId,
      authorization_hash: hash(authorizationPayload),
      workspace_id: workspaceId,
      context_kind: kind,
      context_id: invitationId,
      recipient_hash: hash(recipient),
      recipient_device_id: targetDeviceId,
      permission: "NOT_APPLICABLE",
      share_session_id: "NOT_APPLICABLE",
      share_session_binding_hash: "NOT_APPLICABLE",
      recipient_nonce_state_hash: nonceHash,
      live_redeem_challenge_hash: challengeHash,
      redeem_freshness_proof_hash: hash(freshnessProof),
      previous_workspace_event_sequence: 7,
      previous_workspace_event_hash: headHash,
      admission_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    },
  });
  const acceptedEventAncestry =
    kind === "workspace_invitation" ? workspaceEvents(admission) : guestEvents(admission);
  const last = acceptedEventAncestry.at(-1)!;

  return {
    attempt,
    authorization: { payload: authorizationPayload },
    freshnessProof,
    baseCheckpoint,
    currentCheckpoint: checkpoint(5, Number(last.payload.sequence), eventHash(last)),
    authorityEventAncestry: [created],
    acceptedEventAncestry,
  };
}

function workspaceEvents(admission: SignedKeyDirectoryEnvelope): SignedKeyDirectoryEnvelope[] {
  const memberWrap = nextEvent(admission, "wrap_issued", {
    purpose: "workspace_member_kek_wrap",
  });
  const redeemed = nextEvent(memberWrap, "workspace_invitation_redeemed", {
    workspace_id: workspaceId,
    invitation_id: invitationId,
    redeemed_user_id: targetUserId,
    redeemed_device_id: targetDeviceId,
  });
  return [
    admission,
    memberWrap,
    redeemed,
    nextEvent(redeemed, "wrap_issued", { purpose: "workspace_invitation_kek_wrap" }),
  ];
}

function guestEvents(admission: SignedKeyDirectoryEnvelope): SignedKeyDirectoryEnvelope[] {
  const redeemed = nextEvent(admission, "guest_invitation_redeemed", {
    workspace_id: workspaceId,
    guest_invitation_id: invitationId,
    guest_user_id: targetUserId,
    guest_device_id: targetDeviceId,
  });
  return [
    admission,
    redeemed,
    nextEvent(redeemed, "wrap_issued", { purpose: "guest_invitation_workspace_kek_wrap" }),
  ];
}

function nextEvent(
  previous: SignedKeyDirectoryEnvelope,
  eventType: string,
  body: Record<string, unknown>,
): SignedKeyDirectoryEnvelope {
  return envelope({
    scope_kind: "workspace",
    scope_id: workspaceId,
    sequence: Number(previous.payload.sequence) + 1,
    event_type: eventType,
    previous_event_hash: eventHash(previous),
    body,
  });
}

function checkpoint(
  sequence: number,
  headSequence: number,
  eventHeadHash: string,
): SignedKeyDirectoryEnvelope {
  return envelope({
    scope_kind: "workspace",
    scope_id: workspaceId,
    sequence,
    covered_event_head: { head_sequence: headSequence, head_hash: eventHeadHash },
  });
}

function envelope(payload: Record<string, unknown>): SignedKeyDirectoryEnvelope {
  return { payload, signatures: [{ signer: {}, signature: {} as never }] };
}

function hash(value: unknown): string {
  return blake3Base64Url(canonicalizeStrictBytes(value as StrictJsonValue));
}
