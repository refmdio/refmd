import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { flushPluginRuntimeTeardown } from "./plugin-runtime-teardown";

describe("flushPluginRuntimeTeardown", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not keep application cleanup stuck on a never-settling audit flush", async () => {
    vi.useFakeTimers();
    const flushPendingAudit = vi.fn(() => new Promise<void>(() => undefined));
    let completed = false;

    const teardown = flushPluginRuntimeTeardown(flushPendingAudit, {
      auditFlushTimeoutMs: 25,
    }).then(() => {
      completed = true;
    });

    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(0);
    await Promise.resolve();

    expect(flushPendingAudit).toHaveBeenCalledTimes(1);
    expect(completed).toBe(false);

    await vi.advanceTimersByTimeAsync(24);
    expect(completed).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    await teardown;

    expect(completed).toBe(true);
    expect(flushPendingAudit).toHaveBeenCalledTimes(1);
  });
});
