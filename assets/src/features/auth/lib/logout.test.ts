import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  clearAllPersistedKeys: vi.fn(),
  clearDocumentKeyCache: vi.fn(),
  clearSession: vi.fn(),
  clearSessionData: vi.fn(),
  getCryptoWorker: vi.fn(),
  lock: vi.fn(),
  logout: vi.fn(),
  setCurrentWorkspaceId: vi.fn(),
  terminateCryptoWorker: vi.fn(),
}));

vi.mock("@/entities/document", () => ({
  clearDocumentKeyCache: mocks.clearDocumentKeyCache,
}));

vi.mock("@/shared/api", () => ({
  authApi: {
    logout: mocks.logout,
  },
}));

vi.mock("@/shared/lib/auth-key-persistence", () => ({
  clearAllPersistedKeys: mocks.clearAllPersistedKeys,
  clearSessionData: mocks.clearSessionData,
}));

vi.mock("@/entities/session", () => ({
  clearSession: mocks.clearSession,
}));

vi.mock("@/entities/workspace", () => ({
  setCurrentWorkspaceId: mocks.setCurrentWorkspaceId,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: mocks.getCryptoWorker,
  terminateCryptoWorker: mocks.terminateCryptoWorker,
}));

import { performLogout } from "./logout";

describe("logout", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getCryptoWorker.mockReturnValue({ lock: mocks.lock });
    mocks.lock.mockResolvedValue(undefined);
    mocks.logout.mockResolvedValue(undefined);
    mocks.clearSessionData.mockResolvedValue(undefined);
    mocks.clearAllPersistedKeys.mockResolvedValue(undefined);
  });

  it("clears session state without deleting persisted credentials when requested", async () => {
    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: false,
      redirectPath: "/auth/login",
    });

    expect(mocks.lock).toHaveBeenCalledTimes(1);
    expect(mocks.terminateCryptoWorker).toHaveBeenCalledTimes(1);
    expect(mocks.logout).toHaveBeenCalledTimes(1);
    expect(mocks.clearAllPersistedKeys).not.toHaveBeenCalled();
    expect(mocks.clearSessionData).toHaveBeenCalledTimes(1);
    expect(mocks.clearDocumentKeyCache).toHaveBeenCalledTimes(1);
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
  });

  it("reports an incomplete logout when persisted key cleanup fails", async () => {
    mocks.clearAllPersistedKeys.mockRejectedValueOnce(new Error("delete failed"));

    await expect(performLogout(false)).resolves.toEqual({
      logoutIncomplete: true,
      redirectPath: "/auth/login?logout_incomplete=true",
    });

    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledTimes(1);
    expect(mocks.clearSessionData).toHaveBeenCalledTimes(1);
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
  });

  it("reports an incomplete logout when session cleanup fails after server logout", async () => {
    mocks.clearSessionData.mockRejectedValueOnce(new Error("session cleanup failed"));

    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: true,
      redirectPath: "/auth/login?logout_incomplete=true",
    });

    expect(mocks.logout).toHaveBeenCalledTimes(1);
    expect(mocks.clearAllPersistedKeys).not.toHaveBeenCalled();
    expect(mocks.clearSessionData).toHaveBeenCalledTimes(1);
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
  });

  it("reports an incomplete logout when server logout fails", async () => {
    mocks.logout.mockRejectedValueOnce(new Error("server logout failed"));

    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: true,
      redirectPath: "/auth/login?logout_incomplete=true",
    });

    expect(mocks.logout).toHaveBeenCalledTimes(1);
    expect(mocks.clearSessionData).toHaveBeenCalledTimes(1);
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
  });
});
