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

vi.mock("../../model/register/use-registration-flow", () => ({
  useDeviceRegistrationFlow: () => ({
    phase: () => "done",
    statusMessage: () => "Save your recovery key to finish setting up this account.",
    isRecoveryMode: () => false,
    identityHybridSigningPublicKeyMaterial: () => null,
    devicePublicKeys: () => null,
    clientNonce: () => null,
    dskUnavailableOAuth: () => false,
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
    beginApproval: vi.fn(),
    reloadPage: vi.fn(),
    backToLogin: vi.fn(),
    openRecovery: vi.fn(),
  }),
}));

import { DeviceRegistrationFlow } from "./DeviceRegistrationFlow";

describe("DeviceRegistrationFlow", () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it("renders the current device registration flow", () => {
    const root = document.createElement("div");
    document.body.append(root);

    const dispose = render(() => <DeviceRegistrationFlow />, root);
    expect(document.body.textContent).toContain("New Device");
    expect(document.body.textContent).toContain("Verify this device from an existing device");

    dispose();
  });
});
