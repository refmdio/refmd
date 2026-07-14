import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  registrationChallenge: vi.fn(),
  createRegistration: vi.fn(),
  getRegistrationSas: vi.fn(),
  generateClientNonce: vi.fn(),
  prepareResponderPrekeys: vi.fn(),
  joinSecurityNotifications: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  devicesApi: {
    registrationChallenge: mocks.registrationChallenge,
    createRegistration: mocks.createRegistration,
    getRegistrationSas: mocks.getRegistrationSas,
  },
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({ generateClientNonce: mocks.generateClientNonce }),
}));

vi.mock("@/shared/lib/auth/registration-initial-ake-prekeys", () => ({
  prepareRegistrationInitialAkeResponderPrekeys: mocks.prepareResponderPrekeys,
}));

vi.mock("@/shared/lib/security/notification-channel", () => ({
  joinPendingRegistrationSecurityNotifications: mocks.joinSecurityNotifications,
}));

vi.mock("@/shared/lib/crypto/signature", () => ({
  computeSigningKeyId: () => "identity-signing-key-id",
}));

vi.mock("@/shared/lib/device/metadata", () => ({
  getDeviceName: () => "Test browser",
  getDeviceType: () => "browser",
}));

import type { DeviceRegistrationPublicKeys } from "../../model/register/types";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { startRegistrationApproval } from "./approval-start";

describe("startRegistrationApproval", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.generateClientNonce.mockResolvedValue(new Uint8Array([1, 2, 3]));
    mocks.registrationChallenge.mockResolvedValue({
      registration_challenge: "server-issued-challenge",
    });
    mocks.prepareResponderPrekeys.mockResolvedValue({
      umk_distribution: { payload: { purpose: "umk_distribution" } },
    });
    mocks.createRegistration.mockResolvedValue({ status: "pending" });
    mocks.joinSecurityNotifications.mockResolvedValue({ dispose: vi.fn() });
  });

  it("generates responder prekeys only after the challenge and submits the exact binding", async () => {
    const publicKeys = {
      deviceId: "device-id",
      ecdhPublic: new Uint8Array([4, 5, 6]),
      hybridEncryptionPublicKeyMaterial: { protocol: "encryption-material" },
      encryptionKeyId: "encryption-key-id",
      hybridSigningPublicKeyMaterial: { protocol: "signing-material" },
      signingKeyId: "signing-key-id",
    } as unknown as DeviceRegistrationPublicKeys;
    const identityMaterial = {
      protocol: "identity-signing-material",
    } as unknown as HybridSigningPublicKeyMaterial;

    const result = await startRegistrationApproval({
      userId: "user-id",
      publicKeys,
      identityHybridSigningPublicKeyMaterial: identityMaterial,
      shouldKeepWaiting: () => true,
      onReauthRequired: vi.fn(),
      onApproved: vi.fn(),
      onExpired: vi.fn(),
      onRejected: vi.fn(),
    });

    expect(mocks.prepareResponderPrekeys).toHaveBeenCalledWith({
      userId: "user-id",
      deviceId: "device-id",
      serverChallenge: "server-issued-challenge",
    });
    expect(mocks.createRegistration).toHaveBeenCalledWith(
      expect.objectContaining({
        registration_challenge: "server-issued-challenge",
        ake_responder_prekeys: {
          umk_distribution: { payload: { purpose: "umk_distribution" } },
        },
      }),
      { signal: undefined },
    );
    expect(mocks.registrationChallenge.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.prepareResponderPrekeys.mock.invocationCallOrder[0] ?? 0,
    );
    expect(mocks.prepareResponderPrekeys.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.createRegistration.mock.invocationCallOrder[0] ?? 0,
    );

    if (result.status === "waiting") result.dispose();
  });
});
