import { describe, expect, it } from "vite-plus/test";
import { shouldAutoRedirectReadyDevice } from "./ready-redirect";

describe("shouldAutoRedirectReadyDevice", () => {
  it("redirects an already-ready device session before registration starts", () => {
    expect(
      shouldAutoRedirectReadyDevice({
        authPresent: true,
        needsPasswordReentry: false,
        hasDeviceId: true,
        cryptoWorkerReady: true,
        readyRedirectSuppressed: false,
      }),
    ).toBe(true);
  });

  it("does not redirect while registration flow owns completion navigation", () => {
    expect(
      shouldAutoRedirectReadyDevice({
        authPresent: true,
        needsPasswordReentry: false,
        hasDeviceId: true,
        cryptoWorkerReady: true,
        readyRedirectSuppressed: true,
      }),
    ).toBe(false);
  });
});
