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
});
