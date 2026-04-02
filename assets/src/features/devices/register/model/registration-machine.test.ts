import { describe, expect, it } from "vitest";
import {
  createInitialDeviceRegistrationMachineState,
  transitionDeviceRegistrationState,
} from "./registration-machine";

describe("registration-machine", () => {
  it("moves normal registration into password reentry when device keys are not yet persisted", () => {
    const next = transitionDeviceRegistrationState(createInitialDeviceRegistrationMachineState(), {
      type: "normal_registration_prepared",
      identitySigningPublic: new Uint8Array([1]),
      publicKeys: {
        ecdhPublic: new Uint8Array([2]),
        signingPublic: new Uint8Array([3]),
      },
      needsPassword: true,
      dskUnavailableOAuth: false,
    });

    expect(next.phase).toBe("needs_password");
    expect(next.pendingKeysGenerated).toBe(true);
    expect(next.devicePublicKeys?.signingPublic).toEqual(new Uint8Array([3]));
  });

  it("moves approval into reauth with the pending public keys", () => {
    const publicKeys = {
      ecdhPublic: new Uint8Array([4]),
      signingPublic: new Uint8Array([5]),
    };

    const next = transitionDeviceRegistrationState(createInitialDeviceRegistrationMachineState(), {
      type: "approval_reauth_required",
      clientNonce: new Uint8Array([6]),
      publicKeys,
    });

    expect(next.phase).toBe("reauth");
    expect(next.clientNonce).toEqual(new Uint8Array([6]));
    expect(next.reauthPendingPublicKeys).toBe(publicKeys);
  });

  it("marks recovery password reentry as post-approval persistence", () => {
    const next = transitionDeviceRegistrationState(createInitialDeviceRegistrationMachineState(), {
      type: "recovery_needs_password",
      publicKeys: {
        ecdhPublic: new Uint8Array([7]),
        signingPublic: new Uint8Array([8]),
      },
    });

    expect(next.phase).toBe("needs_password");
    expect(next.postApprovalPersistence).toBe(true);
    expect(next.pendingKeysGenerated).toBe(true);
  });

  it("clears the pending reauth state before returning to the approval flow", () => {
    const seeded = transitionDeviceRegistrationState(
      createInitialDeviceRegistrationMachineState(),
      {
        type: "approval_reauth_required",
        clientNonce: new Uint8Array([9]),
        publicKeys: {
          ecdhPublic: new Uint8Array([10]),
          signingPublic: new Uint8Array([11]),
        },
      },
    );

    const next = transitionDeviceRegistrationState(seeded, {
      type: "reauth_resolved",
    });

    expect(next.reauthLoading).toBe(false);
    expect(next.reauthError).toBeNull();
    expect(next.reauthPendingPublicKeys).toBeNull();
  });

  it("moves the flow to error with the supplied message", () => {
    const next = transitionDeviceRegistrationState(createInitialDeviceRegistrationMachineState(), {
      type: "flow_failed",
      message: "Setup failed",
    });

    expect(next.phase).toBe("error");
    expect(next.error).toBe("Setup failed");
  });
});
