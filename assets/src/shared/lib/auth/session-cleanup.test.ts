import { describe, expect, it, vi } from "vitest";
import { registerBeforeSessionCleanup, runBeforeSessionCleanup } from "./session-cleanup";

describe("session cleanup", () => {
  it("runs secure cleanup callbacks only for secure logout", async () => {
    const always = vi.fn();
    const secureOnly = vi.fn();
    const unregisterAlways = registerBeforeSessionCleanup(always);
    const unregisterSecureOnly = registerBeforeSessionCleanup(secureOnly, { scope: "secure" });

    await runBeforeSessionCleanup({ secure: false });

    expect(always).toHaveBeenCalledTimes(1);
    expect(secureOnly).not.toHaveBeenCalled();

    await runBeforeSessionCleanup({ secure: true });

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

    await runBeforeSessionCleanup({ secure: true });

    expect(calls).toEqual(["runtime:start", "runtime:end", "storage"]);

    unregisterRuntime();
    unregisterStorage();
  });

  it("does not let a hanging before-cleanup callback block later cleanup orders", async () => {
    vi.useFakeTimers();
    const calls: string[] = [];
    const unregisterHanging = registerBeforeSessionCleanup(
      () =>
        new Promise<void>(() => {
          calls.push("hanging:start");
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
    await vi.advanceTimersByTimeAsync(5_000);
    await cleanup;

    expect(calls).toEqual(["hanging:start", "later"]);

    unregisterHanging();
    unregisterLater();
    vi.useRealTimers();
  });
});
