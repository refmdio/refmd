import { render } from "solid-js/web";
import type { JSX } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";

vi.mock("@solidjs/router", () => ({
  A: (props: { href: string; class?: string; children?: JSX.Element }) => (
    <a href={props.href} class={props.class}>
      {props.children}
    </a>
  ),
}));

const oauthMnemonic =
  "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray";

vi.mock("../../model/register/use-registration-flow", () => ({
  useDeviceRegistrationFlow: () => ({
    phase: () => "done",
    statusMessage: () => "Save your recovery key to finish setting up this account.",
    isRecoveryMode: () => false,
    identityHybridSigningPublicKeyMaterial: () => null,
    devicePublicKeys: () => null,
    clientNonce: () => null,
    dskUnavailableOAuth: () => false,
    oauthRecoveryMnemonic: () => oauthMnemonic,
    oauthRecoveryKeyConfirmed: () => false,
    oauthRecoveryKeyVisible: () => false,
    passwordReentryPassword: () => "",
    passwordReentryLoading: () => false,
    passwordReentryError: () => null,
    reauthPassword: () => "",
    reauthLoading: () => false,
    reauthError: () => null,
    error: () => null,
    setPasswordReentryPassword: vi.fn(),
    setReauthPassword: vi.fn(),
    submitPasswordReentry: vi.fn(),
    submitReauth: vi.fn(),
    reloadPage: vi.fn(),
    backToLogin: vi.fn(),
    openRecovery: vi.fn(),
    toggleOAuthRecoveryKeyVisible: vi.fn(),
    copyOAuthRecoveryKey: vi.fn(),
    downloadOAuthRecoveryKey: vi.fn(),
    confirmOAuthRecoveryKey: vi.fn(),
  }),
}));

import { DeviceRegistrationFlow } from "./DeviceRegistrationFlow";

describe("DeviceRegistrationFlow", () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it("requires saving the OAuth first-device recovery key before continuing", () => {
    const root = document.createElement("div");
    document.body.append(root);

    const dispose = render(() => <DeviceRegistrationFlow />, root);
    const continueButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Continue",
    );

    expect(document.body.textContent).toContain("Recovery Key");
    expect(document.body.textContent).toContain("24 words");
    expect(document.body.textContent).toContain("OAuth login alone cannot recover");
    if (!continueButton) throw new Error("Continue button not found");
    expect(continueButton.disabled).toBe(true);

    dispose();
  });
});
