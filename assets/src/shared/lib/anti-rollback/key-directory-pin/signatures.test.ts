import { describe, expect, it } from "vite-plus/test";
import {
  assertShareParticipantCheckpointAdvance,
  isInvitationAdmissionWrapEvent,
  isRecipientBoundDeliveryWrapEvent,
  isRecipientBoundGuestRedeemEvent,
  isRecipientBoundWorkspaceRedeemEvent,
} from "./signatures";
import { eventHash } from "./primitives";
import type { SignedKeyDirectoryEnvelope } from "./types";

const shareSigner = {
  signer_kind: "share_participant_device",
  share_id: "share-1",
  share_participant_principal_id: "principal-1",
  share_participant_device_id: "participant-device-1",
  signing_key_id: "share-signing-key",
};

const otherShareSigner = {
  ...shareSigner,
  share_participant_device_id: "participant-device-2",
  signing_key_id: "other-share-signing-key",
};

const deviceSigner = {
  signer_kind: "device",
  user_id: "user-1",
  device_id: "device-1",
  signing_key_id: "device-signing-key",
};

const previousPayload = {
  covered_event_head: {
    head_hash: "previous-event-hash",
    head_sequence: 1,
  },
  device_keys: [],
  identity_keys: [],
  revoked_key_ids: [],
  share_participant_keys: [{ key_id: shareSigner.signing_key_id }],
};

function checkpointEnvelope(coveredEvent: SignedKeyDirectoryEnvelope): SignedKeyDirectoryEnvelope {
  const state = {
    covered_event_head: {
      head_hash: eventHash(coveredEvent),
      head_sequence: coveredEvent.payload.sequence,
    },
    device_keys: [],
    identity_keys: [],
    revoked_key_ids: [],
    share_participant_keys: [{ key_id: shareSigner.signing_key_id }],
  };
  return {
    payload: state,
    signatures: [{ signature: {}, signer: shareSigner }],
  } as unknown as SignedKeyDirectoryEnvelope;
}

function eventEnvelope(
  eventType: string,
  signer: Record<string, unknown>,
  sequence = 2,
  previousEventHash = "previous-event-hash",
): SignedKeyDirectoryEnvelope {
  return {
    payload: {
      event_type: eventType,
      previous_event_hash: previousEventHash,
      sequence,
    },
    signatures: [{ signature: {}, signer }],
  } as unknown as SignedKeyDirectoryEnvelope;
}

describe("assertShareParticipantCheckpointAdvance", () => {
  it("allows an exact share-participant-signed covered document operation event", () => {
    const coveredEvent = eventEnvelope("document_write_session_admitted", shareSigner);
    const checkpoint = checkpointEnvelope(coveredEvent);

    expect(() =>
      assertShareParticipantCheckpointAdvance(checkpoint, [coveredEvent], previousPayload),
    ).not.toThrow();
  });

  it("rejects a device-signed covered document operation event", () => {
    const coveredEvent = eventEnvelope("document_write_session_admitted", deviceSigner);
    const checkpoint = checkpointEnvelope(coveredEvent);

    expect(() =>
      assertShareParticipantCheckpointAdvance(checkpoint, [coveredEvent], previousPayload),
    ).toThrow("share_participant_checkpoint_signer_missing");
  });

  it("rejects mixed document operation events under one share participant checkpoint", () => {
    const deviceEvent = eventEnvelope("document_write_session_admitted", deviceSigner, 2);
    const shareEvent = eventEnvelope(
      "document_snapshot_accepted",
      shareSigner,
      3,
      eventHash(deviceEvent),
    );
    const checkpoint = checkpointEnvelope(shareEvent);

    expect(() =>
      assertShareParticipantCheckpointAdvance(
        checkpoint,
        [deviceEvent, shareEvent],
        previousPayload,
      ),
    ).toThrow("share_participant_checkpoint_scope_invalid");
  });

  it("rejects document operation events from a different share participant signer", () => {
    const coveredEvent = eventEnvelope("document_write_session_admitted", otherShareSigner);
    const checkpoint = checkpointEnvelope(coveredEvent);

    expect(() =>
      assertShareParticipantCheckpointAdvance(checkpoint, [coveredEvent], previousPayload),
    ).toThrow("share_participant_checkpoint_signer_mismatch");
  });
});

describe("recipient-bound invitation event classification", () => {
  const actor = {
    signer_kind: "device",
    user_id: "owner-user",
    device_id: "owner-device",
    signing_key_id: "owner-signing-key",
  };
  const admission = {
    payload: {
      event_type: "recipient_bound_delivery_admitted",
      body: {
        context_kind: "workspace_invitation",
        context_id: "invitation-1",
        recipient_device_id: "recipient-device",
      },
    },
  } as unknown as SignedKeyDirectoryEnvelope;
  const memberWrap = {
    payload: {
      event_type: "wrap_issued",
      body: {
        purpose: "workspace_member_kek_wrap",
        sender: actor,
        recipient: {
          recipient_kind: "user_identity",
          user_id: "recipient-user",
          key_scope_kind: "user",
          key_scope_id: "recipient-user",
        },
        resource: { workspace_id: "workspace-1", target_user_id: "recipient-user" },
      },
    },
  } as unknown as SignedKeyDirectoryEnvelope;
  const redeemed = {
    payload: {
      event_type: "workspace_invitation_redeemed",
      scope_id: "workspace-1",
      actor,
      body: {
        invitation_id: "invitation-1",
        redeemed_user_id: "recipient-user",
        redeemed_device_id: "recipient-device",
      },
    },
  } as unknown as SignedKeyDirectoryEnvelope;
  const deliveryWrap = {
    payload: {
      event_type: "wrap_issued",
      body: {
        purpose: "workspace_invitation_kek_wrap",
        resource: {
          invitation_id: "invitation-1",
          redeemed_user_id: "recipient-user",
          redeemed_device_id: "recipient-device",
        },
        recipient: {
          recipient_kind: "invitee",
          invitee_user_id: "recipient-user",
          invitee_device_id: "recipient-device",
          key_scope_kind: "user",
          key_scope_id: "recipient-user",
        },
      },
    },
  } as unknown as SignedKeyDirectoryEnvelope;
  const events = [admission, memberWrap, redeemed, deliveryWrap];

  it("recognizes the complete recipient-bound workspace sequence", () => {
    expect(isInvitationAdmissionWrapEvent(memberWrap, redeemed)).toBe(true);
    expect(isRecipientBoundWorkspaceRedeemEvent(redeemed, events)).toBe(true);
    expect(isRecipientBoundDeliveryWrapEvent(deliveryWrap, events)).toBe(true);
  });

  it("rejects a user-directory scope mismatch", () => {
    const mismatched = structuredClone(memberWrap);
    (mismatched.payload.body as Record<string, Record<string, unknown>>).recipient.key_scope_id =
      "other-user";
    const tamperedEvents = [admission, mismatched, redeemed, deliveryWrap];

    expect(isInvitationAdmissionWrapEvent(mismatched, redeemed)).toBe(false);
    expect(isRecipientBoundWorkspaceRedeemEvent(redeemed, tamperedEvents)).toBe(false);
  });

  it("recognizes a recipient-bound guest redemption", () => {
    const guestAdmission = structuredClone(admission);
    (guestAdmission.payload.body as Record<string, unknown>).context_kind = "guest_invitation";
    (guestAdmission.payload.body as Record<string, unknown>).context_id = "guest-invitation-1";
    const guestRedeemed = {
      payload: {
        event_type: "guest_invitation_redeemed",
        body: {
          guest_invitation_id: "guest-invitation-1",
          guest_user_id: "guest-user",
          guest_device_id: "recipient-device",
          recipient_account_user_id: "recipient-user",
          recipient_account_device_id: "recipient-account-device",
        },
      },
    } as unknown as SignedKeyDirectoryEnvelope;

    expect(isRecipientBoundGuestRedeemEvent(guestRedeemed, [guestAdmission, guestRedeemed])).toBe(
      true,
    );
  });
});
