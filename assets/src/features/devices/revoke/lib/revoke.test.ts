import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  base64UrlEncode: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  devicesRevoke: vi.fn(),
  getCryptoWorker: vi.fn(),
  performKekRotation: vi.fn(),
  signMessage: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  cryptoWorkerReady: mocks.cryptoWorkerReady,
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/lib/crypto/encoding", () => ({
  base64UrlEncode: mocks.base64UrlEncode,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: mocks.getCryptoWorker,
}));

vi.mock("../../lib/kek-rotation", () => ({
  performKekRotation: mocks.performKekRotation,
}));

vi.mock("@/shared/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/shared/api")>();
  return {
    ...actual,
    devicesApi: {
      ...actual.devicesApi,
      revoke: mocks.devicesRevoke,
    },
  };
});

import { ApiError } from "@/shared/api";
import { DeviceRevocationError, revokeDevice } from "./revoke";

describe("revoke", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "user_1" } });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.deviceState.mockReturnValue({ deviceId: "device_current" });
    mocks.base64UrlEncode.mockReturnValue("signature_b64");
    mocks.getCryptoWorker.mockReturnValue({
      signMessage: mocks.signMessage,
    });
    mocks.signMessage.mockResolvedValue({ signature: new Uint8Array([1, 2, 3]) });
  });

  it("throws a typed error for retire-blocked revocations", async () => {
    mocks.devicesRevoke.mockRejectedValue(
      new ApiError(409, { error: "retire_blocked_by_unbound_sessions" }),
    );

    let thrown: unknown;
    try {
      await revokeDevice("device_target", "retire");
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(DeviceRevocationError);
    expect((thrown as DeviceRevocationError).code).toBe("retire_blocked_by_unbound_sessions");
  });

  it("returns a warning when KEK rotation fails after security revocation", async () => {
    mocks.devicesRevoke.mockResolvedValue({
      revoked_device_id: "device_target",
      revocation_mode: "security",
      workspaces_needing_kek_rotation: [{ workspace_id: "workspace_1", current_kek_version: 3 }],
    });
    mocks.performKekRotation.mockRejectedValue(new Error("rotation failed"));

    await expect(revokeDevice("device_target", "security")).resolves.toEqual({
      warning:
        "Device removed, but key rotation failed: rotation failed. Keys will be rotated on next access.",
    });
  });
});
