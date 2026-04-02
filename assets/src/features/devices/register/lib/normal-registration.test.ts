import { describe, expect, it } from "vitest";
import { decideNormalRegistrationNextStep } from "./normal-registration";

describe("normal-registration", () => {
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
});
