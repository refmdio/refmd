import { render } from "solid-js/web";
import type { JSX } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const loginPageMock = vi.hoisted(() => ({
  oauthProviders: ["google", "github"] as Array<"google" | "github">,
}));

vi.mock("@solidjs/router", () => ({
  A: (props: { href: string; class?: string; children?: JSX.Element }) => (
    <a href={props.href} class={props.class}>
      {props.children}
    </a>
  ),
}));

vi.mock("../../model/login/use-login-page", () => ({
  useLoginPage: () => ({
    email: () => "",
    setEmail: vi.fn(),
    password: () => "",
    setPassword: vi.fn(),
    rememberMe: () => false,
    setRememberMe: vi.fn(),
    error: () => null,
    loading: () => false,
    oauthLoading: () => null,
    oauthProviders: () => loginPageMock.oauthProviders,
    handleSubmit: vi.fn(),
    handleOAuthStart: vi.fn(),
  }),
}));

import { LoginPage } from "./LoginPage";

describe("LoginPage", () => {
  beforeEach(() => {
    loginPageMock.oauthProviders = ["google", "github"];
  });

  afterEach(() => {
    document.body.replaceChildren();
  });

  it("renders OAuth provider entry points", () => {
    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => <LoginPage />, root);
    const email = document.getElementById("email");
    const password = document.getElementById("password");
    const googleButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.getAttribute("aria-label") === "Continue with Google",
    );

    expect(document.body.textContent).toContain("Continue with Google");
    expect(document.body.textContent).toContain("Continue with GitHub");
    if (!email || !password || !googleButton) throw new Error("OAuth login controls not found");
    expect(email.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
    expect(password.compareDocumentPosition(googleButton) & Node.DOCUMENT_POSITION_FOLLOWING).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );

    dispose();
  });

  it("hides OAuth provider entry points when no providers are configured", () => {
    loginPageMock.oauthProviders = [];

    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => <LoginPage />, root);

    expect(
      Array.from(document.querySelectorAll("button")).some(
        (button) => button.getAttribute("aria-label") === "Continue with Google",
      ),
    ).toBe(false);
    expect(document.body.textContent).not.toContain("Continue with GitHub");

    dispose();
  });
});
