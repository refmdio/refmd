import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  applyRestoredSessionState: vi.fn(),
  restoreOfflineSession: vi.fn(),
  restoreSession: vi.fn(),
  prewarmShareLandingPath: vi.fn(),
  authState: vi.fn(),
  clearSession: vi.fn(),
  setAuthState: vi.fn(),
  setCryptoWorkerReady: vi.fn(),
  setCurrentWorkspaceId: vi.fn(),
  setDeviceState: vi.fn(),
  setSessionContextRestorer: vi.fn(),
  setTofuErrors: vi.fn(),
  isTofuHardFail: vi.fn(),
}));

vi.mock("@/features/auth", () => ({
  applyRestoredSessionState: mocks.applyRestoredSessionState,
  restoreOfflineSession: mocks.restoreOfflineSession,
  restoreSession: mocks.restoreSession,
}));

vi.mock("@/features/share", () => ({
  prewarmShareLandingPath: mocks.prewarmShareLandingPath,
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  clearSession: mocks.clearSession,
  setAuthState: mocks.setAuthState,
  setCryptoWorkerReady: mocks.setCryptoWorkerReady,
  setDeviceState: mocks.setDeviceState,
  setSessionContextRestorer: mocks.setSessionContextRestorer,
  setTofuErrors: mocks.setTofuErrors,
}));

vi.mock("@/entities/workspace", () => ({
  setCurrentWorkspaceId: mocks.setCurrentWorkspaceId,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  isTofuHardFail: mocks.isTofuHardFail,
}));

import { useSessionBootstrap } from "./session";

function pendingPromise<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

describe("useSessionBootstrap", () => {
  let dispose: (() => void) | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    window.history.pushState({}, "", "/");
    mocks.authState.mockReturnValue(null);
    mocks.restoreOfflineSession.mockResolvedValue(null);
    mocks.isTofuHardFail.mockReturnValue(false);
  });

  afterEach(() => {
    dispose?.();
    dispose = undefined;
  });

  it("renders share routes immediately while restoring the user session in the background", async () => {
    const restore = pendingPromise<null>();
    mocks.restoreSession.mockReturnValue(restore.promise);

    const bootstrap = createRoot((disposeRoot) => {
      dispose = disposeRoot;
      window.history.pushState({}, "", "/share/f/folder-token");
      return useSessionBootstrap();
    });

    await vi.waitFor(() => expect(bootstrap.ready()).toBe(true));

    expect(mocks.prewarmShareLandingPath).toHaveBeenCalledTimes(1);
    expect(mocks.restoreSession).toHaveBeenCalledTimes(1);

    restore.resolve(null);
    await vi.waitFor(() => expect(mocks.clearSession).toHaveBeenCalledTimes(1));
  });
});
