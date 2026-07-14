import { describe, expect, it, vi } from "vite-plus/test";
import { registerBeforeSessionCleanup, runBeforeSessionCleanup } from "./session-cleanup";

describe("session cleanup", () => {
  it("runs secure cleanup callbacks only for secure logout", async () => {
    const always = vi.fn();
    const secureOnly = vi.fn();
    const unregisterAlways = registerBeforeSessionCleanup(always);
    const unregisterSecureOnly = registerBeforeSessionCleanup(secureOnly, { scope: "secure" });

    await expect(runBeforeSessionCleanup({ secure: false })).resolves.toEqual({ failures: [] });

    expect(always).toHaveBeenCalledTimes(1);
    expect(secureOnly).not.toHaveBeenCalled();

    await expect(runBeforeSessionCleanup({ secure: true })).resolves.toEqual({ failures: [] });

    expect(always).toHaveBeenCalledTimes(2);
    expect(secureOnly).toHaveBeenCalledTimes(1);

    unregisterAlways();
    unregisterSecureOnly();
  });

  it("runs lower order cleanup callbacks before higher order callbacks", async () => {
    const calls: string[] = [];
    const unregisterRuntime = registerBeforeSessionCleanup(
      async () => {
        calls.push("runtime:start");
        await new Promise<void>((resolve) => queueMicrotask(resolve));
        calls.push("runtime:end");
      },
      { order: -100 },
    );
    const unregisterStorage = registerBeforeSessionCleanup(
      () => {
        calls.push("storage");
      },
      { scope: "secure", order: 100 },
    );

    await expect(runBeforeSessionCleanup({ secure: true })).resolves.toEqual({ failures: [] });

    expect(calls).toEqual(["runtime:start", "runtime:end", "storage"]);

    unregisterRuntime();
    unregisterStorage();
  });

  it("waits for each cleanup order to settle before starting the next order", async () => {
    const calls: string[] = [];
    let finishCleanup!: () => void;
    const unregisterHanging = registerBeforeSessionCleanup(
      () =>
        new Promise<void>((resolve) => {
          calls.push("hanging:start");
          finishCleanup = resolve;
        }),
      { order: -100 },
    );
    const unregisterLater = registerBeforeSessionCleanup(
      () => {
        calls.push("later");
      },
      { order: 100 },
    );

    const cleanup = runBeforeSessionCleanup({ secure: true });
    await Promise.resolve();
    expect(calls).toEqual(["hanging:start"]);

    finishCleanup();
    const result = await cleanup;

    expect(calls).toEqual(["hanging:start", "later"]);
    expect(result.failures).toEqual([]);

    unregisterHanging();
    unregisterLater();
  });

  it("records rejected callbacks and continues the remaining cleanup order", async () => {
    const calls: string[] = [];
    const unregisterRejected = registerBeforeSessionCleanup(
      () => {
        calls.push("rejected");
        throw new Error("cleanup failed");
      },
      { order: -100 },
    );
    const unregisterLater = registerBeforeSessionCleanup(
      () => {
        calls.push("later");
      },
      { order: 100 },
    );

    const result = await runBeforeSessionCleanup({ secure: true });

    expect(calls).toEqual(["rejected", "later"]);
    expect(result.failures).toEqual([
      expect.objectContaining({ callbackId: expect.any(Number), reason: "rejected" }),
    ]);

    unregisterRejected();
    unregisterLater();
  });
});
