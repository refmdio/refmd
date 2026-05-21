import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DeviceInfo } from "@/shared/api/devices";
import type { components } from "@/shared/api/schema";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

const mocks = vi.hoisted(() => ({
  base64UrlDecode: vi.fn(),
  getCryptoWorker: vi.fn(),
  tofuTrustDevice: vi.fn(),
  tofuUpdateLastSeen: vi.fn(),
  tofuVerify: vi.fn(),
  verifyGenesisDeviceBootstrapSignature: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/encoding", () => ({
  base64UrlDecode: mocks.base64UrlDecode,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: mocks.getCryptoWorker,
}));

vi.mock("@/shared/lib/crypto/signature", () => ({
  ed25519PublicKeyFromMaterial: vi.fn(() => new Uint8Array([1, 2, 3])),
}));

import { verifyDeviceListTofu } from "./tofu-verification";

function hybridSigningPublicKeyMaterial(ownerId: string): HybridSigningPublicKeyMaterial {
  return {
    protocol: "refmd.hybrid-signing-key-material",
    version: 1,
    owner_kind: "device",
    owner_id: ownerId,
    ed25519_public: "ed",
    mldsa65_public: "ml",
    suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
    suite_rank: 1000,
  };
}

function createDevice(overrides: Partial<DeviceInfo>): DeviceInfo {
  return {
    id: "device_1",
    name: "Device",
    device_type: "desktop",
    hybrid_signing_public_key_material: {
      ed25519_public: "sig",
    } as unknown as DeviceInfo["hybrid_signing_public_key_material"],
    signing_key_id: "signing-key-id",
    hybrid_encryption_public_key_material: {
      mlkem768_public: "mlkem",
      x25519_public: "ecdh",
    } as unknown as DeviceInfo["hybrid_encryption_public_key_material"],
    encryption_key_id: "encryption-key-id",
    approval_signature: {
      signature: "identity",
    } as unknown as DeviceInfo["approval_signature"],
    approval_signature_surface: "genesis_device_bootstrap",
    approval_proof: {} as unknown as components["schemas"]["DeviceApprovalProof"],
    key_checkpoint_sequence: 1,
    key_checkpoint_hash: "checkpoint-hash",
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
      verifyGenesisDeviceBootstrapSignature: mocks.verifyGenesisDeviceBootstrapSignature,
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
        identityHybridSigningPublicKeyMaterial: hybridSigningPublicKeyMaterial("user_1"),
      }),
    ).resolves.toEqual({
      hardFailMessage: "Laptop: Identity key changed — possible key compromise",
      warnings: [],
    });
  });

  it("adds warnings for unverified devices without trusting first-seen device-list keys", async () => {
    mocks.tofuVerify.mockResolvedValueOnce({ status: "first_seen" });
    mocks.tofuVerify.mockResolvedValueOnce({ status: "known_trusted" });
    mocks.verifyGenesisDeviceBootstrapSignature.mockResolvedValueOnce(true);

    const result = await verifyDeviceListTofu({
      devices: [
        createDevice({ id: "device_2", name: "Phone", device_type: "mobile" }),
        createDevice({
          id: "device_3",
          name: "Tablet",
          device_type: "mobile",
          approval_signature: undefined,
          client_nonce: undefined,
        }),
      ],
      userId: "user_1",
      identityHybridSigningPublicKeyMaterial: hybridSigningPublicKeyMaterial("user_1"),
    });

    expect(result).toEqual({
      hardFailMessage: null,
      warnings: ["Tablet: Missing identity signature — device approval cannot be verified"],
    });
    expect(mocks.tofuTrustDevice).not.toHaveBeenCalled();
    expect(mocks.tofuUpdateLastSeen).not.toHaveBeenCalled();
  });
});
