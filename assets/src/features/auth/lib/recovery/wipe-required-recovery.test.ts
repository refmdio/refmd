import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  clearAllPersistedKeys: vi.fn(),
  clearDocumentKeyCache: vi.fn(),
  clearSession: vi.fn(),
  clearSessionData: vi.fn(),
  lock: vi.fn(),
  resetPhoenixConnection: vi.fn(),
  runSessionCleanup: vi.fn(),
  setCurrentWorkspaceId: vi.fn(),
  setSecureLogoutIncomplete: vi.fn(),
  terminateAllScopedCryptoWorkers: vi.fn(),
  terminateCryptoWorker: vi.fn(),
}));

vi.mock("@/entities/document", () => ({
  clearDocumentKeyCache: mocks.clearDocumentKeyCache,
}));

vi.mock("@/entities/session", () => ({
  clearSession: mocks.clearSession,
}));

vi.mock("@/entities/workspace", () => ({
  setCurrentWorkspaceId: mocks.setCurrentWorkspaceId,
}));

vi.mock("@/shared/lib/auth/key-persistence", () => ({
  clearAllPersistedKeys: mocks.clearAllPersistedKeys,
  clearSessionData: mocks.clearSessionData,
}));

vi.mock("@/shared/lib/auth/logout-incomplete", () => ({
  setSecureLogoutIncomplete: mocks.setSecureLogoutIncomplete,
}));

vi.mock("@/shared/lib/auth/session-cleanup", () => ({
  runSessionCleanup: mocks.runSessionCleanup,
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

import { wipePredecessorDeviceBeforeIdentityRecovery } from "./wipe-required-recovery";

describe("wipePredecessorDeviceBeforeIdentityRecovery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.lock.mockResolvedValue(undefined);
    mocks.clearSessionData.mockResolvedValue(undefined);
    mocks.clearAllPersistedKeys.mockResolvedValue(undefined);
  });

  it("destroys predecessor runtime and persistence before allowing recovery", async () => {
    await expect(wipePredecessorDeviceBeforeIdentityRecovery()).resolves.toBeUndefined();

    expect(mocks.setSecureLogoutIncomplete).toHaveBeenNthCalledWith(1, true);
    expect(mocks.lock).toHaveBeenCalledOnce();
    expect(mocks.terminateCryptoWorker).toHaveBeenCalledOnce();
    expect(mocks.terminateAllScopedCryptoWorkers).toHaveBeenCalledOnce();
    expect(mocks.resetPhoenixConnection).toHaveBeenCalledOnce();
    expect(mocks.clearDocumentKeyCache).toHaveBeenCalledOnce();
    expect(mocks.runSessionCleanup).toHaveBeenCalledOnce();
    expect(mocks.clearSession).toHaveBeenCalledOnce();
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: false });
    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledOnce();
    expect(mocks.setSecureLogoutIncomplete).toHaveBeenLastCalledWith(false);
  });

  it("remains fail closed when any persistence deletion fails", async () => {
    mocks.clearSessionData.mockRejectedValueOnce(new Error("session delete failed"));

    await expect(wipePredecessorDeviceBeforeIdentityRecovery()).rejects.toThrow(
      "identity_recovery_local_wipe_incomplete",
    );

    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledOnce();
    expect(mocks.setSecureLogoutIncomplete).toHaveBeenCalledTimes(1);
    expect(mocks.setSecureLogoutIncomplete).toHaveBeenCalledWith(true);
  });

  it("continues destructive cleanup when the predecessor worker cannot lock", async () => {
    mocks.lock.mockRejectedValueOnce(new Error("worker unavailable"));

    await expect(wipePredecessorDeviceBeforeIdentityRecovery()).resolves.toBeUndefined();

    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledOnce();
    expect(mocks.setSecureLogoutIncomplete).toHaveBeenLastCalledWith(false);
  });
});
