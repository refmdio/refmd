import type { components } from "@/shared/api";
import { checkpointHash, eventHash } from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { describe, expect, it, vi } from "vite-plus/test";
import {
  assertRecipientDeliveryAdmissionBindings,
  recipientDeliveryOperationProof,
  verifyRecipientDeliveryAdmission,
} from "@/shared/lib/anti-rollback/key-directory-pin/recipient-delivery-admission";

const pinMocks = vi.hoisted(() => ({
  get: vi.fn(),
  has: vi.fn(),
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("@/shared/lib/anti-rollback/key-directory-pin/pins")>();
  return {
    ...original,
    getKeyDirectoryPin: pinMocks.get,
    hasVerifiedKeyDirectoryEvent: pinMocks.has,
  };
});

type DeliveryAttempt = components["schemas"]["InvitationDeliveryAttemptResponse"];

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

function fixture(kind: "workspace_invitation" | "guest_invitation") {
  const attempt = {
    approved_artifacts: null,
    authorization_id: authorizationId,
    context_id: invitationId,
    context_kind: kind,
    context_snapshot: {},
    created_at: "2026-07-14T00:00:00Z",
    expires_at: "2026-07-14T01:00:00Z",
    live_redeem_challenge_hash: challengeHash,
    recipient_device_id: targetDeviceId,
    recipient_nonce_state_hash: nonceHash,
    recipient_redeem_nonce: "recipient-redeem-nonce",
    recipient_user_id: targetUserId,
    redeem_attempt_id: attemptId,
    request_binding_hash: hash({ request: attemptId }),
    resource_hash: resourceHash,
    status: "approved",
    target_device_id: targetDeviceId,
    target_encryption_key_id: encryptionKeyId,
    target_registration: {} as never,
    target_user_id: targetUserId,
    workspace_id: workspaceId,
  } satisfies DeliveryAttempt;
  const createdType = `${kind}_created`;
  const invitationIdField =
    kind === "workspace_invitation" ? "invitation_id" : "guest_invitation_id";
  const created = envelope({
    scope_kind: "workspace",
    scope_id: workspaceId,
    sequence: 7,
    event_type: createdType,
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
    recipient_redeem_nonce: "recipient-redeem-nonce",
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
  const events =
    kind === "workspace_invitation" ? workspaceEvents(admission) : guestEvents(admission);
  const last = events.at(-1)!;
  const currentCheckpoint = checkpoint(5, Number(last.payload.sequence), eventHash(last));
  return {
    attempt,
    authorization: { payload: authorizationPayload },
    freshnessProof,
    baseCheckpoint,
    currentCheckpoint,
    authorityEventAncestry: [created],
    acceptedEventAncestry: events,
  };
}

describe("recipient-bound delivery admission", () => {
  it.each(["workspace_invitation", "guest_invitation"] as const)(
    "accepts one exact active %s admission",
    (kind) => {
      const value = fixture(kind);
      expect(assertRecipientDeliveryAdmissionBindings(value)).toBe(value.acceptedEventAncestry[0]);
    },
  );

  it("rejects missing, duplicate, and non-ancestor admissions", () => {
    const missing = fixture("workspace_invitation");
    missing.acceptedEventAncestry.shift();
    expect(() => assertRecipientDeliveryAdmissionBindings(missing)).toThrow(
      "recipient_delivery_admission_count_invalid",
    );

    const duplicate = fixture("workspace_invitation");
    const copy = structuredClone(duplicate.acceptedEventAncestry[0]!);
    (copy.payload.body as Record<string, unknown>).admission_nonce =
      "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    duplicate.acceptedEventAncestry.push(copy);
    expect(() => assertRecipientDeliveryAdmissionBindings(duplicate)).toThrow(
      "recipient_delivery_admission_count_invalid",
    );

    const nonAncestor = fixture("workspace_invitation");
    const last = nonAncestor.acceptedEventAncestry.at(-1)!;
    (
      nonAncestor.currentCheckpoint.payload.covered_event_head as Record<string, unknown>
    ).head_hash = hash({ not: eventHash(last) });
    expect(() => assertRecipientDeliveryAdmissionBindings(nonAncestor)).toThrow(
      "recipient_delivery_admission_not_ancestor",
    );
  });

  it.each([
    ["authorization hash", "authorization_hash", hash({ wrong: "authorization" })],
    ["context", "context_id", "77777777-7777-4777-8777-777777777777"],
    ["device", "recipient_device_id", "88888888-8888-4888-8888-888888888888"],
    ["permission", "permission", "view"],
    ["nonce state", "recipient_nonce_state_hash", hash({ wrong: "nonce" })],
    ["challenge", "live_redeem_challenge_hash", hash({ wrong: "challenge" })],
    ["freshness", "redeem_freshness_proof_hash", hash({ wrong: "freshness" })],
    ["previous head", "previous_workspace_event_hash", hash({ wrong: "head" })],
  ])("rejects a mutated %s binding", (_label, field, value) => {
    const subject = fixture("workspace_invitation");
    (subject.acceptedEventAncestry[0]!.payload.body as Record<string, unknown>)[field] = value;
    expect(() => assertRecipientDeliveryAdmissionBindings(subject)).toThrow(
      "recipient_delivery_admission_binding_mismatch",
    );
  });

  it("rejects a substituted authorization recipient", () => {
    const subject = fixture("guest_invitation");
    const payload = subject.authorization.payload as Record<string, unknown>;
    (payload.recipient as Record<string, unknown>).recipient_principal_id =
      "99999999-9999-4999-8999-999999999999";
    expect(() => assertRecipientDeliveryAdmissionBindings(subject)).toThrow(
      "recipient_delivery_authorization_binding_mismatch",
    );
  });

  it.each(["workspace_invitation_revoked", "workspace_invitation_redeemed"])(
    "rejects %s in the invitation pre-state",
    (eventType) => {
      const subject = fixture("workspace_invitation");
      subject.authorityEventAncestry.push(
        envelope({
          scope_kind: "workspace",
          scope_id: workspaceId,
          sequence: 7,
          event_type: eventType,
          previous_event_hash: hash({ before: eventType }),
          body: { workspace_id: workspaceId, invitation_id: invitationId },
        }),
      );
      expect(() => assertRecipientDeliveryAdmissionBindings(subject)).toThrow(
        "recipient_delivery_invitation_inactive",
      );
    },
  );

  it("rejects expired pre-state and post-admission revocation", () => {
    const expired = fixture("guest_invitation");
    (expired.authorityEventAncestry[0]!.payload.body as Record<string, unknown>)[
      "expires_event_sequence"
    ] = 8;
    expect(() => assertRecipientDeliveryAdmissionBindings(expired)).toThrow(
      "recipient_delivery_invitation_inactive",
    );

    const revoked = fixture("guest_invitation");
    const previous = revoked.acceptedEventAncestry.at(-1)!;
    const revocation = envelope({
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: Number(previous.payload.sequence) + 1,
      event_type: "guest_invitation_revoked",
      previous_event_hash: eventHash(previous),
      body: { workspace_id: workspaceId, guest_invitation_id: invitationId },
    });
    revoked.acceptedEventAncestry.push(revocation);
    const head = revoked.currentCheckpoint.payload.covered_event_head as Record<string, unknown>;
    head.head_sequence = revocation.payload.sequence;
    head.head_hash = eventHash(revocation);
    expect(() => assertRecipientDeliveryAdmissionBindings(revoked)).toThrow(
      "recipient_delivery_post_admission_invalidated",
    );
  });

  it("requires the opaque verification token before constructing an open proof", () => {
    expect(() => recipientDeliveryOperationProof({} as never, { purpose: "test" })).toThrow(
      "recipient_delivery_admission_required",
    );
  });

  it("issues the token only when the exact admission is in the current pin", async () => {
    const subject = fixture("workspace_invitation");
    const currentPayload = subject.currentCheckpoint.payload;
    const currentHead = currentPayload.covered_event_head as Record<string, unknown>;
    pinMocks.get.mockResolvedValue({
      checkpointSequence: currentPayload.sequence,
      checkpointHash: checkpointHash(subject.currentCheckpoint),
      eventHeadSequence: currentHead.head_sequence,
      eventHeadHash: currentHead.head_hash,
    });
    pinMocks.has.mockReturnValue(true);

    const admission = await verifyRecipientDeliveryAdmission(subject);
    expect(recipientDeliveryOperationProof(admission, { purpose: "test" })).toEqual({
      purpose: "test",
    });

    pinMocks.has.mockReturnValue(false);
    await expect(verifyRecipientDeliveryAdmission(subject)).rejects.toThrow(
      "recipient_delivery_admission_not_in_pinned_chain",
    );
  });
});

function workspaceEvents(admission: SignedKeyDirectoryEnvelope): SignedKeyDirectoryEnvelope[] {
  const memberWrap = nextEvent(admission, "wrap_issued", { purpose: "workspace_member_kek_wrap" });
  const redeemed = nextEvent(memberWrap, "workspace_invitation_redeemed", {
    workspace_id: workspaceId,
    invitation_id: invitationId,
    redeemed_user_id: targetUserId,
    redeemed_device_id: targetDeviceId,
  });
  const delivery = nextEvent(redeemed, "wrap_issued", {
    purpose: "workspace_invitation_kek_wrap",
  });
  return [admission, memberWrap, redeemed, delivery];
}

function guestEvents(admission: SignedKeyDirectoryEnvelope): SignedKeyDirectoryEnvelope[] {
  const redeemed = nextEvent(admission, "guest_invitation_redeemed", {
    workspace_id: workspaceId,
    guest_invitation_id: invitationId,
    guest_user_id: targetUserId,
    guest_device_id: targetDeviceId,
  });
  const delivery = nextEvent(redeemed, "wrap_issued", {
    purpose: "guest_invitation_workspace_kek_wrap",
  });
  return [admission, redeemed, delivery];
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
  return {
    payload,
    signatures: [{ signer: {}, signature: {} as never }],
  };
}

function hash(value: unknown): string {
  return blake3Base64Url(canonicalizeStrictBytes(value as StrictJsonValue));
}
