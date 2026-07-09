import { render } from "solid-js/web";
import type { JSX } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const registerPageMock = vi.hoisted(() => ({
  oauthProviders: ["google", "github"] as Array<"google" | "github">,
}));

vi.mock("@solidjs/router", () => ({
  A: (props: { href: string; class?: string; children?: JSX.Element }) => (
    <a href={props.href} class={props.class}>
      {props.children}
    </a>
  ),
}));

vi.mock("../../model/register/use-register-page", () => ({
  useRegisterPage: () => ({
    name: () => "",
    setName: vi.fn(),
    email: () => "",
    setEmail: vi.fn(),
    password: () => "",
    setPassword: vi.fn(),
    confirmPassword: () => "",
    setConfirmPassword: vi.fn(),
    error: () => null,
    loading: () => false,
    oauthLoading: () => null,
    oauthProviders: () => registerPageMock.oauthProviders,
    recoveryMnemonic: () => null,
    mnemonicConfirmed: () => false,
    showMnemonic: () => false,
    setShowMnemonic: vi.fn(),
    handleSubmit: vi.fn(),
    handleOAuthStart: vi.fn(),
    handleCopyRecoveryKey: vi.fn(),
    handleDownloadRecoveryKey: vi.fn(),
    handleConfirmMnemonic: vi.fn(),
  }),
}));

import { RegisterPage } from "./RegisterPage";

describe("RegisterPage", () => {
  beforeEach(() => {
    registerPageMock.oauthProviders = ["google", "github"];
  });

  afterEach(() => {
    document.body.replaceChildren();
  });

  it("renders OAuth provider entry points", () => {
    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => <RegisterPage />, root);
    const email = document.getElementById("email");
    const password = document.getElementById("password");
    const confirmPassword = document.getElementById("confirm-password");
    const googleButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.getAttribute("aria-label") === "Continue with Google",
    );

    expect(document.body.textContent).toContain("Continue with Google");
    expect(document.body.textContent).toContain("Continue with GitHub");
    if (!email || !password || !confirmPassword || !googleButton) {
      throw new Error("OAuth register controls not found");
    }
    expect(email.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
    expect(
      confirmPassword.compareDocumentPosition(googleButton) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
    expect(
      password.compareDocumentPosition(confirmPassword) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBe(Node.DOCUMENT_POSITION_FOLLOWING);

    dispose();
  });

  it("hides OAuth provider entry points when no providers are configured", () => {
    registerPageMock.oauthProviders = [];

    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => <RegisterPage />, root);

    expect(
      Array.from(document.querySelectorAll("button")).some(
        (button) => button.getAttribute("aria-label") === "Continue with Google",
      ),
    ).toBe(false);
    expect(document.body.textContent).not.toContain("Continue with GitHub");

    dispose();
  });
});
