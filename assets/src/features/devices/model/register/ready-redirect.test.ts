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
        oauthRecoveryMnemonic: null,
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
        oauthRecoveryMnemonic: null,
      }),
    ).toBe(false);
  });

  it("does not redirect while OAuth first-device recovery key is waiting to be saved", () => {
    expect(
      shouldAutoRedirectReadyDevice({
        authPresent: true,
        needsPasswordReentry: false,
        hasDeviceId: true,
        cryptoWorkerReady: true,
        readyRedirectSuppressed: false,
        oauthRecoveryMnemonic: "word ".repeat(24).trim(),
      }),
    ).toBe(false);
  });
});
