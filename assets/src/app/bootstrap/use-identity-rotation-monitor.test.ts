import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  getStatus: vi.fn(),
  rotate: vi.fn(),
  setDeadline: vi.fn(),
}));

vi.mock("solid-js", () => ({
  createEffect: (effect: () => void) => effect(),
  onCleanup: vi.fn(),
}));
vi.mock("@/entities/session", () => ({
  authState: () => ({
    sessionId: "guest-session",
    user: { id: "guest-user", accountType: "guest" },
  }),
  cryptoWorkerReady: () => true,
  deviceState: () => ({ deviceId: "guest-device" }),
}));
vi.mock("@/features/devices", () => ({
  rotateCurrentUserIdentity: mocks.rotate,
}));
vi.mock("@/shared/api", () => ({
  encryptionApi: { getIdentityRotationStatus: mocks.getStatus },
}));
vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({ setIdentityRotationDeadline: mocks.setDeadline }),
}));
vi.mock("@/shared/lib/key-directory/fetch", () => ({ fetchVerifiedKeyDirectory: vi.fn() }));
vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  lookupVerifiedKeyDirectoryCheckpointBodies: vi.fn(() => []),
}));
vi.mock("@/shared/lib/logger", () => ({ clientError: vi.fn() }));

import { useIdentityRotationMonitor } from "./use-identity-rotation-monitor";

describe("useIdentityRotationMonitor", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    mocks.getStatus.mockResolvedValue({
      rotation_due_at: "2020-01-01T00:00:00Z",
      pending_key_version: 2,
      needs_rotation: true,
    });
    mocks.rotate.mockResolvedValue({ rotation_due_at: "2030-01-01T00:00:00Z" });
  });

  afterEach(() => vi.useRealTimers());

  it("schedules and completes overdue rotation for a persisted guest session", async () => {
    useIdentityRotationMonitor();
    await vi.advanceTimersByTimeAsync(0);

    expect(mocks.getStatus).toHaveBeenCalledWith({ rrpDeviceId: "guest-device" });
    expect(mocks.setDeadline).toHaveBeenCalledWith("2020-01-01T00:00:00Z");
    expect(mocks.rotate).toHaveBeenCalledOnce();
  });
});
