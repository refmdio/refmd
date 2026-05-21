import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  clearAllPersistedKeys: vi.fn(),
  clearStoredShareParticipantSessions: vi.fn(),
  clearDocumentKeyCache: vi.fn(),
  clearSession: vi.fn(),
  clearSessionData: vi.fn(),
  clearMountTrustAnchorsWithDsk: vi.fn(),
  getCryptoWorker: vi.fn(),
  getDeviceId: vi.fn(),
  lock: vi.fn(),
  logout: vi.fn(),
  resetPhoenixConnection: vi.fn(),
  restoreSessionContext: vi.fn(),
  setCurrentWorkspaceId: vi.fn(),
  getPreferredSessionScope: vi.fn(),
  setPreferredSessionScope: vi.fn(),
  terminateCryptoWorker: vi.fn(),
  terminateAllScopedCryptoWorkers: vi.fn(),
}));

vi.mock("@/entities/document", () => ({
  clearDocumentKeyCache: mocks.clearDocumentKeyCache,
}));

vi.mock("@/shared/api", () => ({
  authApi: {
    logout: mocks.logout,
  },
}));

vi.mock("@/shared/lib/auth/key-persistence", () => ({
  clearAllPersistedKeys: mocks.clearAllPersistedKeys,
  clearSessionData: mocks.clearSessionData,
}));

vi.mock("@/shared/lib/auth/share-participant-session-store", () => ({
  clearStoredShareParticipantSessions: mocks.clearStoredShareParticipantSessions,
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  clearSession: mocks.clearSession,
  restoreSessionContext: mocks.restoreSessionContext,
}));

vi.mock("@/entities/workspace", () => ({
  setCurrentWorkspaceId: mocks.setCurrentWorkspaceId,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: mocks.getCryptoWorker,
  terminateCryptoWorker: mocks.terminateCryptoWorker,
}));

vi.mock("@/shared/lib/crypto/worker/scoped", () => ({
  terminateAllScopedCryptoWorkers: mocks.terminateAllScopedCryptoWorkers,
}));

vi.mock("@/shared/lib/ws/phoenix-channel", () => ({
  resetPhoenixConnection: mocks.resetPhoenixConnection,
}));

vi.mock("@/shared/lib/auth/session-scope", () => ({
  getPreferredSessionScope: mocks.getPreferredSessionScope,
  setPreferredSessionScope: mocks.setPreferredSessionScope,
}));

import { performLogout } from "./logout";

describe("logout", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getCryptoWorker.mockReturnValue({
      clearMountTrustAnchorsWithDsk: mocks.clearMountTrustAnchorsWithDsk,
      getDeviceId: mocks.getDeviceId,
      lock: mocks.lock,
    });
    mocks.getDeviceId.mockResolvedValue("share-device-id");
    mocks.lock.mockResolvedValue(undefined);
    mocks.logout.mockResolvedValue(undefined);
    mocks.getPreferredSessionScope.mockReturnValue(null);
    mocks.authState.mockReturnValue({ user: { id: "user-id" } });
    mocks.restoreSessionContext.mockResolvedValue(undefined);
    mocks.clearSessionData.mockResolvedValue(undefined);
    mocks.clearAllPersistedKeys.mockResolvedValue(undefined);
    mocks.clearMountTrustAnchorsWithDsk.mockResolvedValue(undefined);
    mocks.clearStoredShareParticipantSessions.mockResolvedValue(undefined);
    window.history.replaceState({}, "", "/dashboard");
  });

  it("clears session state without deleting persisted credentials when requested", async () => {
    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: false,
      redirectPath: "/auth/login",
    });

    expect(mocks.lock).toHaveBeenCalledTimes(1);
    expect(mocks.terminateCryptoWorker).toHaveBeenCalledTimes(1);
    expect(mocks.resetPhoenixConnection).toHaveBeenCalledTimes(1);
    expect(mocks.logout).toHaveBeenCalledTimes(1);
    expect(mocks.clearAllPersistedKeys).not.toHaveBeenCalled();
    expect(mocks.clearStoredShareParticipantSessions).not.toHaveBeenCalled();
    expect(mocks.clearMountTrustAnchorsWithDsk).not.toHaveBeenCalled();
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: true });
    expect(mocks.clearDocumentKeyCache).toHaveBeenCalledTimes(1);
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
  });

  it("preserves share participant state for non-secure share-scoped logout", async () => {
    mocks.getPreferredSessionScope.mockReturnValue("share");

    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: false,
      redirectPath: "/dashboard",
    });

    expect(mocks.logout).not.toHaveBeenCalled();
    expect(mocks.clearStoredShareParticipantSessions).not.toHaveBeenCalled();
    expect(mocks.clearMountTrustAnchorsWithDsk).not.toHaveBeenCalled();
    expect(mocks.clearAllPersistedKeys).not.toHaveBeenCalled();
    expect(mocks.clearSessionData).not.toHaveBeenCalled();
    expect(mocks.clearSession).not.toHaveBeenCalled();
    expect(mocks.setCurrentWorkspaceId).not.toHaveBeenCalled();
    expect(mocks.setPreferredSessionScope).not.toHaveBeenCalled();
    expect(mocks.restoreSessionContext).toHaveBeenCalledTimes(1);
  });

  it("uses the share session selector for explicit secure share-scoped logout", async () => {
    mocks.getPreferredSessionScope.mockReturnValue("share");

    await expect(performLogout(false)).resolves.toEqual({
      logoutIncomplete: false,
      redirectPath: "/dashboard",
    });

    expect(mocks.logout).toHaveBeenCalledWith({
      clearMountSession: true,
      sessionScope: "share",
    });
    expect(mocks.clearStoredShareParticipantSessions).toHaveBeenCalledTimes(1);
    expect(mocks.clearMountTrustAnchorsWithDsk).toHaveBeenCalledTimes(1);
    expect(mocks.clearAllPersistedKeys).not.toHaveBeenCalled();
    expect(mocks.clearSessionData).not.toHaveBeenCalled();
    expect(mocks.clearSession).not.toHaveBeenCalled();
    expect(mocks.setPreferredSessionScope).toHaveBeenCalledWith(null);
  });

  it("reports an incomplete logout when persisted key cleanup fails", async () => {
    mocks.clearAllPersistedKeys.mockRejectedValueOnce(new Error("delete failed"));

    await expect(performLogout(false)).resolves.toEqual({
      logoutIncomplete: true,
      redirectPath: "/auth/login?logout_incomplete=true",
    });

    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledTimes(1);
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: false });
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.resetPhoenixConnection).toHaveBeenCalledTimes(1);
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
  });

  it("reports an incomplete logout when share participant cleanup fails", async () => {
    mocks.clearStoredShareParticipantSessions.mockRejectedValueOnce(new Error("delete failed"));

    await expect(performLogout(false)).resolves.toEqual({
      logoutIncomplete: true,
      redirectPath: "/auth/login?logout_incomplete=true",
    });

    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledTimes(1);
    expect(mocks.clearStoredShareParticipantSessions).toHaveBeenCalledTimes(1);
    expect(mocks.clearMountTrustAnchorsWithDsk).toHaveBeenCalledTimes(1);
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: false });
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
  });

  it("reports an incomplete logout when session cleanup fails after server logout", async () => {
    mocks.clearSessionData.mockRejectedValueOnce(new Error("session cleanup failed"));

    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: true,
      redirectPath: "/auth/login?logout_incomplete=true",
    });

    expect(mocks.logout).toHaveBeenCalledTimes(1);
    expect(mocks.clearAllPersistedKeys).not.toHaveBeenCalled();
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: true });
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.resetPhoenixConnection).toHaveBeenCalledTimes(1);
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
  });

  it("clears user and share credentials on explicit secure logout", async () => {
    await expect(performLogout(false)).resolves.toEqual({
      logoutIncomplete: false,
      redirectPath: "/auth/login",
    });

    expect(mocks.logout).toHaveBeenCalledWith({ clearMountSession: true });
    expect(mocks.logout).toHaveBeenCalledWith({
      clearMountSession: true,
      sessionScope: "share",
    });
    expect(mocks.clearAllPersistedKeys).toHaveBeenCalledTimes(1);
    expect(mocks.clearStoredShareParticipantSessions).toHaveBeenCalledTimes(1);
    expect(mocks.clearMountTrustAnchorsWithDsk).toHaveBeenCalledTimes(1);
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: false });
  });

  it("preserves share participant state during normal user logout", async () => {
    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: false,
      redirectPath: "/auth/login",
    });

    expect(mocks.logout).toHaveBeenCalledWith({ clearMountSession: false });
    expect(mocks.logout).not.toHaveBeenCalledWith({
      clearMountSession: true,
      sessionScope: "share",
    });
    expect(mocks.clearStoredShareParticipantSessions).not.toHaveBeenCalled();
    expect(mocks.clearMountTrustAnchorsWithDsk).not.toHaveBeenCalled();
  });

  it("reports an incomplete logout when server logout fails", async () => {
    mocks.logout.mockRejectedValueOnce(new Error("server logout failed"));

    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: true,
      redirectPath: "/auth/login?logout_incomplete=true",
    });

    expect(mocks.logout).toHaveBeenCalledTimes(1);
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: true });
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.resetPhoenixConnection).toHaveBeenCalledTimes(1);
    expect(mocks.setCurrentWorkspaceId).toHaveBeenCalledWith(null);
  });

  it("keeps the user session alive but marks logout incomplete when share context restore fails", async () => {
    mocks.getPreferredSessionScope.mockReturnValue("share");
    mocks.restoreSessionContext.mockRejectedValueOnce(new Error("restore failed"));
    window.history.replaceState({}, "", "/share/d/token-123");

    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: true,
      redirectPath: "/share/d/token-123?logout_incomplete=true",
    });

    expect(mocks.clearSessionData).not.toHaveBeenCalled();
    expect(mocks.clearSession).not.toHaveBeenCalled();
    expect(mocks.setCurrentWorkspaceId).not.toHaveBeenCalled();
  });

  it("still resets documents and socket when worker lock fails", async () => {
    mocks.lock.mockRejectedValueOnce(new Error("worker already gone"));

    await expect(performLogout(true)).resolves.toEqual({
      logoutIncomplete: false,
      redirectPath: "/auth/login",
    });

    expect(mocks.terminateCryptoWorker).toHaveBeenCalledTimes(1);
    expect(mocks.terminateAllScopedCryptoWorkers).toHaveBeenCalledTimes(1);
    expect(mocks.resetPhoenixConnection).toHaveBeenCalledTimes(1);
  });
});
