import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const apiMocks = vi.hoisted(() => ({
  create: vi.fn(),
  get: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  workspacesApi: {
    createInvitationDeliveryAttempt: apiMocks.create,
    getInvitationDeliveryAttempt: apiMocks.get,
  },
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: vi.fn(),
}));

import {
  getApprovedGuestDeliveryAttempt,
  InvitationDeliveryTerminalError,
} from "./delivery-attempt";

const lookupToken = "lookup-token";
const storageKey = `refmd-invitation-delivery-attempt:${lookupToken}`;
const invitationId = "11111111-1111-4111-8111-111111111111";
const accountUserId = "22222222-2222-4222-8222-222222222222";
const accountDeviceId = "33333333-3333-4333-8333-333333333333";
const guestUserId = "44444444-4444-4444-8444-444444444444";
const guestDeviceId = "55555555-5555-4555-8555-555555555555";

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  localStorage.setItem(
    storageKey,
    JSON.stringify({
      attemptId: "66666666-6666-4666-8666-666666666666",
      contextId: invitationId,
      recipientUserId: accountUserId,
      recipientDeviceId: accountDeviceId,
      recipientRedeemNonce: "nonce",
      liveRedeemChallengeHash: "challenge",
    }),
  );
});

describe("known guest delivery attempt lifecycle", () => {
  it.each(["consumed", "expired"] as const)(
    "rejects a %s initial attempt and clears its local tuple",
    async (status) => {
      apiMocks.get.mockResolvedValue({ status });

      await expect(getAttempt()).rejects.toBeInstanceOf(InvitationDeliveryTerminalError);

      expect(localStorage.getItem(storageKey)).toBeNull();
      expect(apiMocks.create).not.toHaveBeenCalled();
    },
  );

  it("clears the local tuple when the server no longer has the attempt", async () => {
    apiMocks.get.mockRejectedValue(new Error("not_found"));

    await expect(getAttempt()).rejects.toThrow("no longer available");

    expect(localStorage.getItem(storageKey)).toBeNull();
    expect(apiMocks.create).not.toHaveBeenCalled();
  });
});

function getAttempt() {
  return getApprovedGuestDeliveryAttempt({
    token: lookupToken,
    lookup: {
      kind: "guest",
      delivery_mode: "known_recipient",
      invitation_id: invitationId,
      recipient_user_id: accountUserId,
      recipient_device_ids: [accountDeviceId],
    } as never,
    auth: { user: { id: accountUserId } } as never,
    device: { deviceId: accountDeviceId } as never,
    target: {
      userId: guestUserId,
      deviceId: guestDeviceId,
      registration: {} as never,
      registrationProof: {},
    },
  });
}
