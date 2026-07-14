import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { createRoot, createSignal } from "solid-js";

const mocks = vi.hoisted(() => ({
  performKekRotation: vi.fn(),
}));

vi.mock("@/features/devices", () => ({
  performKekRotation: mocks.performKekRotation,
}));

vi.mock("@/entities/session", () => ({
  authState: vi.fn(() => ({ user: { id: "user-1" } })),
  cryptoWorkerReady: vi.fn(() => true),
  deviceState: vi.fn(() => ({ deviceId: "device-1" })),
}));

import {
  canInitiateWorkspaceRotation,
  createRotationRetryScheduler,
  useWorkspaceKekRotationMonitor,
} from "./use-workspace-kek-rotation-monitor";

const workspace = {
  workspace_id: "workspace-1",
  current_kek_version: 1,
  kek_rotation_initiator_user_id: null,
  current_user_base_role: "owner",
};

describe("canInitiateWorkspaceRotation", () => {
  it("allows the assigned initiator", () => {
    expect(
      canInitiateWorkspaceRotation(
        {
          ...workspace,
          kek_rotation_initiator_user_id: "user-1",
          current_user_base_role: "viewer",
        },
        "user-1",
      ),
    ).toBe(true);
  });

  it.each(["owner", "admin"])("allows an eligible %s to claim an unassigned rotation", (role) => {
    expect(
      canInitiateWorkspaceRotation({ ...workspace, current_user_base_role: role }, "user-1"),
    ).toBe(true);
  });

  it("rejects non-privileged users when rotation is unassigned", () => {
    expect(
      canInitiateWorkspaceRotation({ ...workspace, current_user_base_role: "editor" }, "user-1"),
    ).toBe(false);
  });

  it("does not replace another assigned initiator", () => {
    expect(
      canInitiateWorkspaceRotation(
        { ...workspace, kek_rotation_initiator_user_id: "user-2" },
        "user-1",
      ),
    ).toBe(false);
  });
});

describe("createRotationRetryScheduler", () => {
  afterEach(() => vi.useRealTimers());

  it("schedules one retry and permits another after it fires", async () => {
    vi.useFakeTimers();
    const retry = vi.fn();
    const scheduler = createRotationRetryScheduler(retry, 1_000);

    scheduler.schedule();
    scheduler.schedule();
    expect(scheduler.pending()).toBe(true);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(retry).toHaveBeenCalledOnce();
    expect(scheduler.pending()).toBe(false);

    scheduler.schedule();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(retry).toHaveBeenCalledTimes(2);
  });

  it("cancels a pending retry after rotation is no longer required", async () => {
    vi.useFakeTimers();
    const retry = vi.fn();
    const scheduler = createRotationRetryScheduler(retry, 1_000);

    scheduler.schedule();
    scheduler.cancel();
    await vi.advanceTimersByTimeAsync(1_000);

    expect(retry).not.toHaveBeenCalled();
    expect(scheduler.pending()).toBe(false);
  });

  it("cannot be rescheduled by a late rejection after disposal", async () => {
    vi.useFakeTimers();
    const retry = vi.fn();
    const scheduler = createRotationRetryScheduler(retry, 1_000);

    scheduler.schedule();
    scheduler.dispose();
    scheduler.schedule();
    await vi.advanceTimersByTimeAsync(1_000);

    expect(retry).not.toHaveBeenCalled();
    expect(scheduler.pending()).toBe(false);
  });
});

describe("useWorkspaceKekRotationMonitor", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("retries a transient failure through query invalidation without a concurrent duplicate", async () => {
    vi.useFakeTimers();
    mocks.performKekRotation
      .mockRejectedValueOnce(new Error("temporary"))
      .mockResolvedValueOnce(undefined);
    const invalidateQueries = vi.fn(async () => undefined);
    const [pending] = createSignal([workspace]);
    const dispose = createRoot((disposeRoot) => {
      useWorkspaceKekRotationMonitor(pending, { invalidateQueries } as never);
      return disposeRoot;
    });

    await vi.waitFor(() => expect(mocks.performKekRotation).toHaveBeenCalledOnce());
    await Promise.resolve();
    expect(mocks.performKekRotation).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.waitFor(() => expect(mocks.performKekRotation).toHaveBeenCalledTimes(2));

    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: ["workspaces"] });
    dispose();
  });

  it("does not retry a late rejection after pending work disappears", async () => {
    vi.useFakeTimers();
    let rejectRotation!: (error: Error) => void;
    mocks.performKekRotation.mockImplementationOnce(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectRotation = reject;
        }),
    );
    const invalidateQueries = vi.fn(async () => undefined);
    const [pending, setPending] = createSignal([workspace]);
    const dispose = createRoot((disposeRoot) => {
      useWorkspaceKekRotationMonitor(pending, { invalidateQueries } as never);
      return disposeRoot;
    });

    await vi.waitFor(() => expect(mocks.performKekRotation).toHaveBeenCalledOnce());
    setPending([]);
    rejectRotation(new Error("late"));
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(1_000);

    expect(mocks.performKekRotation).toHaveBeenCalledOnce();
    expect(invalidateQueries).not.toHaveBeenCalled();
    dispose();
  });

  it("does not retry a late rejection after hook cleanup", async () => {
    vi.useFakeTimers();
    let rejectRotation!: (error: Error) => void;
    mocks.performKekRotation.mockImplementationOnce(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectRotation = reject;
        }),
    );
    const invalidateQueries = vi.fn(async () => undefined);
    const [pending] = createSignal([workspace]);
    const dispose = createRoot((disposeRoot) => {
      useWorkspaceKekRotationMonitor(pending, { invalidateQueries } as never);
      return disposeRoot;
    });

    await vi.waitFor(() => expect(mocks.performKekRotation).toHaveBeenCalledOnce());
    dispose();
    rejectRotation(new Error("late"));
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(1_000);

    expect(mocks.performKekRotation).toHaveBeenCalledOnce();
    expect(invalidateQueries).not.toHaveBeenCalled();
  });
});
