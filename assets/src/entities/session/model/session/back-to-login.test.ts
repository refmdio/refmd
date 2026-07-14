import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  clearSession: vi.fn(),
  clearSessionData: vi.fn(),
  logout: vi.fn(),
  resetPhoenixConnection: vi.fn(),
  runBeforeSessionCleanup: vi.fn(),
  runSessionCleanup: vi.fn(),
  terminateAllScopedCryptoWorkers: vi.fn(),
  terminateCryptoWorker: vi.fn(),
}));

vi.mock("@/shared/api", () => ({ authApi: { logout: mocks.logout } }));
vi.mock("@/shared/lib/auth/key-persistence", () => ({
  clearSessionData: mocks.clearSessionData,
}));
vi.mock("@/shared/lib/auth/session-cleanup", () => ({
  runBeforeSessionCleanup: mocks.runBeforeSessionCleanup,
  runSessionCleanup: mocks.runSessionCleanup,
}));
vi.mock("@/shared/lib/crypto/worker/client", () => ({
  terminateCryptoWorker: mocks.terminateCryptoWorker,
}));
vi.mock("@/shared/lib/crypto/worker/scoped", () => ({
  terminateAllScopedCryptoWorkers: mocks.terminateAllScopedCryptoWorkers,
}));
vi.mock("@/shared/lib/ws/phoenix-channel", () => ({
  resetPhoenixConnection: mocks.resetPhoenixConnection,
}));
vi.mock("../auth/state", () => ({
  authState: mocks.authState,
  clearSession: mocks.clearSession,
}));

import { returnToLogin } from "./back-to-login";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.authState.mockReturnValue({ user: { id: "user-id" } });
  mocks.logout.mockResolvedValue(undefined);
  mocks.runBeforeSessionCleanup.mockResolvedValue({ failures: [] });
  mocks.clearSessionData.mockResolvedValue(undefined);
});

describe("ordinary return to login", () => {
  it("clears only volatile session state and preserves encrypted persistence", async () => {
    await returnToLogin();

    expect(mocks.logout).toHaveBeenCalledWith({ clearMountSession: false });
    expect(mocks.runBeforeSessionCleanup).toHaveBeenCalledWith({ secure: false });
    expect(mocks.resetPhoenixConnection).toHaveBeenCalledOnce();
    expect(mocks.terminateCryptoWorker).toHaveBeenCalledOnce();
    expect(mocks.terminateAllScopedCryptoWorkers).toHaveBeenCalledOnce();
    expect(mocks.runSessionCleanup).toHaveBeenCalledOnce();
    expect(mocks.clearSession).toHaveBeenCalledOnce();
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: true });
  });

  it("still performs local volatile cleanup when server logout fails", async () => {
    mocks.logout.mockRejectedValue(new Error("offline"));

    await returnToLogin();

    expect(mocks.clearSession).toHaveBeenCalledOnce();
    expect(mocks.clearSessionData).toHaveBeenCalledWith({ preserveAuthBootstrap: true });
  });
});
