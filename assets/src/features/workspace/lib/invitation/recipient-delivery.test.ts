import { describe, expect, it } from "vite-plus/test";
import {
  invitationRecipientAadUserId,
  invitationRecipientDelivery,
  invitationRecipientToken,
  normalizeInvitationRecipient,
} from "./recipient-delivery";

const publicMaterial = {
  protocol: "refmd.hybrid-encryption-key-material" as const,
  version: 1 as const,
  suite_id:
    "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65" as const,
  suite_rank: 1000 as const,
  owner_kind: "device" as const,
  owner_id: "22222222-2222-4222-8222-222222222222",
  x25519_public: "x",
  mlkem768_public: "m",
  hybrid_public: "h",
};

describe("invitation recipient model", () => {
  it("keeps unknown recipients on fragment delivery", () => {
    const recipient = normalizeInvitationRecipient({
      delivery_mode: "unknown_fragment",
      recipient_user_id: null,
      devices: [],
    });
    expect(invitationRecipientAadUserId(recipient)).toBe("NOT_APPLICABLE");
    expect(invitationRecipientToken(recipient, "lookup", "secret")).toBe("lookup.secret");
    expect(invitationRecipientDelivery(recipient)).toBeUndefined();
  });

  it("uses recipient-bound delivery and omits the fragment for known recipients", () => {
    const recipient = normalizeInvitationRecipient({
      delivery_mode: "known_recipient",
      recipient_user_id: "11111111-1111-4111-8111-111111111111",
      devices: [
        {
          device_id: "22222222-2222-4222-8222-222222222222",
          encryption_key_id: "key-id",
          hybrid_encryption_public_key_material: publicMaterial,
          signing_key_id: "signing-key-id",
          hybrid_signing_public_key_material: {} as never,
          key_checkpoint_sequence: 7,
          key_checkpoint_hash: "user-checkpoint",
        },
      ],
    });
    const delivery = invitationRecipientDelivery(recipient);

    expect(invitationRecipientToken(recipient, "lookup", "secret")).toBe("lookup");
    expect(delivery).toEqual({ recipientUserId: recipient.recipient_user_id });
  });

  it("rejects an underspecified unknown-recipient response", () => {
    expect(() =>
      normalizeInvitationRecipient({ delivery_mode: "unknown_fragment" } as never),
    ).toThrow("invitation_recipient_response_invalid");
  });

  it("rejects a known response without an active device", () => {
    expect(() =>
      normalizeInvitationRecipient({
        delivery_mode: "known_recipient",
        recipient_user_id: "11111111-1111-4111-8111-111111111111",
        devices: [],
      }),
    ).toThrow("invitation_recipient_response_invalid");
  });
});
