import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DeviceInfo } from "@/shared/api/devices";

const mocks = vi.hoisted(() => ({
  base64UrlDecode: vi.fn(),
  getCryptoWorker: vi.fn(),
  tofuTrustDevice: vi.fn(),
  tofuUpdateLastSeen: vi.fn(),
  tofuVerify: vi.fn(),
  verifyDeviceIdentitySignature: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/encoding", () => ({
  base64UrlDecode: mocks.base64UrlDecode,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: mocks.getCryptoWorker,
}));

import { verifyDeviceListTofu } from "./tofu-verification";

function createDevice(overrides: Partial<DeviceInfo>): DeviceInfo {
  return {
    id: "device_1",
    name: "Device",
    device_type: "desktop",
    signing_public_key: "sig",
    ecdh_public_key: "ecdh",
    identity_signature: "identity",
    client_nonce: "nonce",
    created_at: "2026-03-31T00:00:00Z",
    last_seen_at: "2026-03-31T00:00:00Z",
    ...overrides,
  };
}

describe("tofu-verification", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.base64UrlDecode.mockReturnValue(new Uint8Array([1, 2, 3]));
    mocks.getCryptoWorker.mockReturnValue({
      tofuVerify: mocks.tofuVerify,
      verifyDeviceIdentitySignature: mocks.verifyDeviceIdentitySignature,
      tofuTrustDevice: mocks.tofuTrustDevice,
      tofuUpdateLastSeen: mocks.tofuUpdateLastSeen,
    });
  });

  it("returns a hard-fail message when a device identity key changes", async () => {
    mocks.tofuVerify.mockResolvedValueOnce({ status: "identity_key_changed" });

    await expect(
      verifyDeviceListTofu({
        devices: [createDevice({ id: "device_1", name: "Laptop" })],
        userId: "user_1",
        identitySigningPublic: new Uint8Array([9]),
      }),
    ).resolves.toEqual({
      hardFailMessage: "Laptop: Identity key changed — possible key compromise",
      warnings: [],
    });
  });

  it("adds warnings for unverified devices and trusts first-seen verified devices", async () => {
    mocks.tofuVerify.mockResolvedValueOnce({ status: "first_seen" });
    mocks.tofuVerify.mockResolvedValueOnce({ status: "known_trusted" });
    mocks.verifyDeviceIdentitySignature.mockResolvedValueOnce(true);

    const result = await verifyDeviceListTofu({
      devices: [
        createDevice({ id: "device_2", name: "Phone", device_type: "mobile" }),
        createDevice({
          id: "device_3",
          name: "Tablet",
          device_type: "mobile",
          identity_signature: undefined,
          client_nonce: undefined,
        }),
      ],
      userId: "user_1",
      identitySigningPublic: new Uint8Array([9]),
    });

    expect(result).toEqual({
      hardFailMessage: null,
      warnings: ["Tablet: Missing identity signature — device approval cannot be verified"],
    });
    expect(mocks.tofuTrustDevice).toHaveBeenCalledTimes(1);
    expect(mocks.tofuUpdateLastSeen).not.toHaveBeenCalled();
  });
});
