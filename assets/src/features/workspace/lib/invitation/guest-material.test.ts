import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const workerMocks = vi.hoisted(() => ({
  deleteMaterial: vi.fn(),
  loadStoredDsk: vi.fn(),
  sha256Hash: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    deleteGuestInvitationMaterialWithDsk: workerMocks.deleteMaterial,
    loadStoredDsk: workerMocks.loadStoredDsk,
    sha256Hash: workerMocks.sha256Hash,
  }),
}));

import { forgetGuestRedeemMaterial } from "./guest-material";

beforeEach(() => {
  vi.clearAllMocks();
  workerMocks.loadStoredDsk.mockResolvedValue(true);
  workerMocks.sha256Hash.mockResolvedValue("token-hash");
  workerMocks.deleteMaterial.mockResolvedValue(undefined);
});

describe("guest redeem material lifecycle", () => {
  it("deletes both invitation-scoped and active pending material on terminal cleanup", async () => {
    await forgetGuestRedeemMaterial("dGVzdA", {
      body: {
        guest_user_id: "11111111-1111-4111-8111-111111111111",
        device_id: "22222222-2222-4222-8222-222222222222",
      } as never,
      publicKeys: {} as never,
    });

    expect(workerMocks.deleteMaterial).toHaveBeenNthCalledWith(1, "refmd-guest-redeem:token-hash");
    expect(workerMocks.deleteMaterial).toHaveBeenNthCalledWith(
      2,
      "refmd-guest-active:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222",
    );
  });

  it("does not touch encrypted stores when no DSK is available", async () => {
    workerMocks.loadStoredDsk.mockResolvedValue(false);

    await forgetGuestRedeemMaterial("dGVzdA", {
      body: {} as never,
      publicKeys: {} as never,
    });

    expect(workerMocks.deleteMaterial).not.toHaveBeenCalled();
  });
});
