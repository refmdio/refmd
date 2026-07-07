import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  deviceState: vi.fn(),
  devicesList: vi.fn(),
  getCryptoWorker: vi.fn(),
  getPersistedDeviceId: vi.fn(),
  hasStoredDeviceKeys: vi.fn(),
  getSalt: vi.fn(),
  hasStoredDsk: vi.fn(),
  init: vi.fn(),
  initFromPassword: vi.fn(),
  isReady: vi.fn(),
  loadAuthBootstrap: vi.fn(),
  me: vi.fn(),
  persistCurrentKeysWithDsk: vi.fn(),
  storeAuthBootstrap: vi.fn(),
  setCryptoWorkerReady: vi.fn(),
  setFullSession: vi.fn(),
  setTofuErrors: vi.fn(),
  getPublicKeys: vi.fn(),
  clearTransientKeys: vi.fn(),
  tofuVerifyAllDevices: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  authApi: {
    getSalt: mocks.getSalt,
    me: mocks.me,
  },
  devicesApi: {
    list: mocks.devicesList,
  },
  ApiError: class ApiError extends Error {
    status: number;
    constructor(status: number) {
      super("api error");
      this.status = status;
    }
  },
}));

vi.mock("@/shared/lib/auth/key-persistence", () => ({
  getPersistedDeviceId: mocks.getPersistedDeviceId,
  persistCurrentKeysWithDsk: mocks.persistCurrentKeysWithDsk,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: mocks.getCryptoWorker,
  isTofuHardFail: () => false,
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  deviceState: mocks.deviceState,
  setCryptoWorkerReady: mocks.setCryptoWorkerReady,
  setFullSession: mocks.setFullSession,
  setTofuErrors: mocks.setTofuErrors,
}));

import { restoreSession } from "./session";
import { restoreKeysFromPassword } from "./restore-keys-from-password";

const meResponse = {
  user_id: "user-1",
  email: "user@example.com",
  name: "User",
  account_type: "password",
  session_id: "session-1",
  device_id: "device-1",
  device_verified: true,
  device_key_checkpoint_sequence: 1,
  device_key_checkpoint_hash: "checkpoint-hash",
  key_restore_endpoint_ref: "auth-key-restore-v1",
  is_recovery: false,
  remember_me: true,
  expires_at: "2026-06-02T00:00:00Z",
  auth_type: "password",
};

describe("session key restoration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getCryptoWorker.mockReturnValue({
      clearTransientKeys: mocks.clearTransientKeys,
      getPublicKeys: mocks.getPublicKeys,
      hasStoredDeviceKeys: mocks.hasStoredDeviceKeys,
      hasStoredDsk: mocks.hasStoredDsk,
      init: mocks.init,
      initFromPassword: mocks.initFromPassword,
      isReady: mocks.isReady,
      loadAuthBootstrap: mocks.loadAuthBootstrap,
      storeAuthBootstrap: mocks.storeAuthBootstrap,
      tofuVerifyAllDevices: mocks.tofuVerifyAllDevices,
    });
    mocks.me.mockResolvedValue({ ...meResponse });
    mocks.getSalt.mockResolvedValue({
      salt: "AA",
      kdf_params: { memory: 8, iterations: 1, parallelism: 1 },
    });
    mocks.hasStoredDsk.mockResolvedValue(true);
    mocks.hasStoredDeviceKeys.mockResolvedValue(true);
    mocks.loadAuthBootstrap.mockResolvedValue({
      userId: "user-1",
      email: "user@example.com",
      name: "User",
      deviceId: "device-1",
      deviceSigningKeyId: "device-signing-1",
      cachedAt: 1,
    });
    mocks.getPersistedDeviceId.mockReturnValue(null);
    mocks.clearTransientKeys.mockResolvedValue(undefined);
    mocks.devicesList.mockResolvedValue({ devices: [] });
    mocks.tofuVerifyAllDevices.mockResolvedValue({ errors: [] });
    mocks.persistCurrentKeysWithDsk.mockResolvedValue(undefined);
    mocks.storeAuthBootstrap.mockResolvedValue(true);
  });

  it("keeps the cached device signing key id when reload requires password reentry", async () => {
    mocks.init.mockRejectedValueOnce(new Error("stale wrapped UMK"));

    const result = await restoreSession();

    expect(result).toMatchObject({
      needsPasswordReentry: true,
      deviceId: "device-1",
      deviceSigningKeyId: "device-signing-1",
      workerReady: false,
    });
  });

  it("keeps the authenticated session but requires device recovery when local device keys are unavailable", async () => {
    mocks.hasStoredDeviceKeys.mockResolvedValue(false);

    const result = await restoreSession();

    expect(result).toMatchObject({
      userId: "user-1",
      deviceId: "device-1",
      deviceVerified: false,
      needsPasswordReentry: false,
      workerReady: false,
    });
    expect(mocks.init).not.toHaveBeenCalled();
    expect(mocks.initFromPassword).not.toHaveBeenCalled();
  });

  it("uses cached device signing key id for password reentry when state lacks it", async () => {
    mocks.authState.mockReturnValue({
      user: { id: "user-1", email: "user@example.com", name: "User" },
      sessionId: "session-1",
      expiresAt: "2026-06-02T00:00:00Z",
      identityHybridSigningPublicKeyMaterial: null,
      identityEcdhPublic: null,
    });
    mocks.deviceState.mockReturnValue({
      deviceId: "device-1",
      deviceSigningKeyId: null,
      deviceHybridSigningPublicKeyMaterial: null,
      deviceEcdhPublic: null,
    });
    mocks.initFromPassword.mockResolvedValue({ authKey: new Uint8Array([1]) });
    mocks.isReady.mockResolvedValue(true);
    mocks.getPublicKeys.mockResolvedValue({
      deviceSigningKeyId: "device-signing-1",
      deviceHybridSigningPublicKeyMaterial: null,
      deviceEcdhPublic: null,
      identityHybridSigningPublicKeyMaterial: null,
      identityEcdhPublic: null,
    });

    await restoreKeysFromPassword("correct-password");

    expect(mocks.initFromPassword).toHaveBeenCalledWith(
      expect.objectContaining({
        useStoredDsk: true,
        deviceSigningKeyId: "device-signing-1",
      }),
    );
    expect(mocks.setCryptoWorkerReady).toHaveBeenCalledWith(true);
  });

  it("reports unavailable local device keys when password restore cannot make the worker ready", async () => {
    mocks.authState.mockReturnValue({
      user: { id: "user-1", email: "user@example.com", name: "User" },
      sessionId: "session-1",
      expiresAt: "2026-06-02T00:00:00Z",
      identityHybridSigningPublicKeyMaterial: null,
      identityEcdhPublic: null,
    });
    mocks.deviceState.mockReturnValue({
      deviceId: "device-1",
      deviceSigningKeyId: null,
      deviceHybridSigningPublicKeyMaterial: null,
      deviceEcdhPublic: null,
    });
    mocks.initFromPassword.mockResolvedValue({ authKey: new Uint8Array([1]) });
    mocks.isReady.mockResolvedValue(false);

    await expect(restoreKeysFromPassword("correct-password")).rejects.toThrow(
      "Local device keys are unavailable. Return to login and register this device again.",
    );
  });
});
