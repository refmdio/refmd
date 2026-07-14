import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  logout: vi.fn(),
  clearAllPersistedKeys: vi.fn(),
  clearSessionData: vi.fn(),
  lock: vi.fn(),
  resetPhoenixConnection: vi.fn(),
  terminateAllScopedCryptoWorkers: vi.fn(),
  terminateCryptoWorker: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  authApi: { logout: mocks.logout },
  ApiError: class ApiError extends Error {
    readonly status: number;
    readonly body: Record<string, unknown>;

    constructor(status: number, body: Record<string, unknown>) {
      super(`API error ${status}`);
      this.status = status;
      this.body = body;
    }
  },
}));

vi.mock("./key-persistence", () => ({
  clearAllPersistedKeys: mocks.clearAllPersistedKeys,
  clearSessionData: mocks.clearSessionData,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({ lock: mocks.lock }),
  terminateCryptoWorker: mocks.terminateCryptoWorker,
}));

vi.mock("@/shared/lib/crypto/worker/scoped", () => ({
  terminateAllScopedCryptoWorkers: mocks.terminateAllScopedCryptoWorkers,
}));

vi.mock("@/shared/lib/ws/phoenix-channel", () => ({
  resetPhoenixConnection: mocks.resetPhoenixConnection,
}));

import {
  isSecureLogoutIncomplete,
  retrySecureLogoutCleanup,
  setSecureLogoutIncomplete,
} from "./logout-incomplete";
import { ApiError } from "@/shared/api";
import { registerBeforeSessionCleanup } from "./session-cleanup";

describe("secure logout incomplete gate", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
    mocks.logout.mockResolvedValue(undefined);
    mocks.clearSessionData.mockResolvedValue(undefined);
    mocks.clearAllPersistedKeys.mockResolvedValue(undefined);
    mocks.lock.mockResolvedValue(undefined);
  });

  it("keeps reauthentication blocked until retry cleanup succeeds", async () => {
    setSecureLogoutIncomplete(true);
    expect(isSecureLogoutIncomplete()).toBe(true);

    await retrySecureLogoutCleanup();

    expect(mocks.logout).toHaveBeenCalledWith({
      clearMountSession: true,
      sessionScope: "share",
    });
    expect(mocks.logout).toHaveBeenCalledWith({ clearMountSession: true });
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: false });
    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledTimes(1);
    expect(mocks.lock).toHaveBeenCalledOnce();
    expect(mocks.terminateCryptoWorker).toHaveBeenCalledOnce();
    expect(mocks.terminateAllScopedCryptoWorkers).toHaveBeenCalledOnce();
    expect(mocks.resetPhoenixConnection).toHaveBeenCalledOnce();
    expect(isSecureLogoutIncomplete()).toBe(false);
  });

  it("retains the gate but still attempts local persistence when server cleanup fails", async () => {
    setSecureLogoutIncomplete(true);
    mocks.logout.mockRejectedValueOnce(new Error("server logout failed"));

    await expect(retrySecureLogoutCleanup()).rejects.toThrow("secure_logout_cleanup_incomplete");

    expect(mocks.logout).toHaveBeenCalledTimes(2);
    expect(mocks.clearSessionData).toHaveBeenCalledOnce();
    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledOnce();
    expect(isSecureLogoutIncomplete()).toBe(true);
  });

  it("treats an already absent server session as successfully invalidated", async () => {
    setSecureLogoutIncomplete(true);
    mocks.logout.mockRejectedValueOnce(new ApiError(401, { error: "unauthorized" }));

    await expect(retrySecureLogoutCleanup()).resolves.toBeUndefined();

    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledOnce();
    expect(isSecureLogoutIncomplete()).toBe(false);
  });

  it("retains the gate when retry cleanup fails", async () => {
    setSecureLogoutIncomplete(true);
    mocks.clearAllPersistedKeys.mockRejectedValueOnce(new Error("delete failed"));

    await expect(retrySecureLogoutCleanup()).rejects.toThrow("secure_logout_cleanup_incomplete");

    expect(isSecureLogoutIncomplete()).toBe(true);
  });

  it("reruns failed secure lifecycle callbacks before clearing the gate", async () => {
    setSecureLogoutIncomplete(true);
    let attempts = 0;
    const unregister = registerBeforeSessionCleanup(
      () => {
        attempts += 1;
        if (attempts === 1) throw new Error("lifecycle cleanup failed");
      },
      { scope: "secure" },
    );

    try {
      await expect(retrySecureLogoutCleanup()).rejects.toThrow("secure_logout_cleanup_incomplete");
      expect(isSecureLogoutIncomplete()).toBe(true);

      await expect(retrySecureLogoutCleanup()).resolves.toBeUndefined();
      expect(attempts).toBe(2);
      expect(isSecureLogoutIncomplete()).toBe(false);
    } finally {
      unregister();
    }
  });
});
