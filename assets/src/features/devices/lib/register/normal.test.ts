import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const { me } = vi.hoisted(() => ({
  me: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  authApi: {
    me,
  },
}));

import { decideNormalRegistrationNextStep, prepareNormalRegistration } from "./normal";

describe("normal", () => {
  beforeEach(() => {
    me.mockReset();
  });

  it("requires password reentry when device keys could not be persisted with DSK", () => {
    expect(
      decideNormalRegistrationNextStep({
        hasDsk: true,
        deviceKeysPersisted: false,
        authType: "password",
      }),
    ).toEqual({
      kind: "needs_password",
      dskUnavailableOAuth: false,
    });
  });

  it("continues immediately when DSK persistence succeeds", () => {
    expect(
      decideNormalRegistrationNextStep({
        hasDsk: true,
        deviceKeysPersisted: true,
        authType: "password",
      }),
    ).toEqual({
      kind: "ready",
      dskUnavailableOAuth: false,
    });
  });

  it("requires password reentry when the browser cannot persist DSK and auth is password", () => {
    expect(
      decideNormalRegistrationNextStep({
        hasDsk: false,
        deviceKeysPersisted: false,
        authType: "password",
      }),
    ).toEqual({
      kind: "needs_password",
      dskUnavailableOAuth: false,
    });
  });

  it("falls back to session-only keys for OAuth when DSK is unavailable", () => {
    expect(
      decideNormalRegistrationNextStep({
        hasDsk: false,
        deviceKeysPersisted: false,
        authType: "oauth",
      }),
    ).toEqual({
      kind: "ready",
      dskUnavailableOAuth: true,
    });
  });

  it("routes OAuth sessions without identity material into first-device bootstrap", async () => {
    me.mockResolvedValueOnce({
      auth_type: null,
      identity_hybrid_signing_public_key_material: null,
    });

    await expect(prepareNormalRegistration("user-1")).resolves.toEqual({
      kind: "oauth_first_device_required",
    });
  });
});
