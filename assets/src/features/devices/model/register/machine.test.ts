import { describe, expect, it } from "vitest";
import {
  createInitialDeviceRegistrationMachineState,
  transitionDeviceRegistrationState,
} from "./machine";
import type { DeviceRegistrationPublicKeys } from "./types";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

function hybridSigningPublicKeyMaterial(ownerId: string): HybridSigningPublicKeyMaterial {
  return {
    protocol: "refmd.hybrid-signing-key-material",
    version: 1,
    owner_kind: "device",
    owner_id: ownerId,
    ed25519_public: "ed",
    mldsa65_public: "ml",
    suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
    suite_rank: 1000,
  };
}

function makePublicKeys(deviceId: string, ecdhPublic: Uint8Array): DeviceRegistrationPublicKeys {
  return {
    deviceId,
    ecdhPublic,
    hybridEncryptionPublicKeyMaterial: {
      protocol: "refmd.hybrid-encryption-key-material",
      version: 1,
      owner_kind: "device",
      owner_id: deviceId,
      x25519_public: "x",
      mlkem768_public: "mlkem",
      hybrid_public: "hybrid",
      suite_id:
        "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
      suite_rank: 1000,
    },
    encryptionKeyId: `${deviceId}-encryption-key`,
    hybridSigningPublicKeyMaterial: {
      protocol: "refmd.hybrid-signing-key-material",
      version: 1,
      owner_kind: "device",
      owner_id: deviceId,
      ed25519_public: "ed",
      mldsa65_public: "ml",
      suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
      suite_rank: 1000,
    },
    signingKeyId: `${deviceId}-signing-key`,
  };
}

describe("machine", () => {
  it("moves normal registration into password reentry when device keys are not yet persisted", () => {
    const next = transitionDeviceRegistrationState(createInitialDeviceRegistrationMachineState(), {
      type: "normal_registration_prepared",
      identityHybridSigningPublicKeyMaterial: hybridSigningPublicKeyMaterial("user-1"),
      publicKeys: makePublicKeys("device-1", new Uint8Array([2])),
      needsPassword: true,
      dskUnavailableOAuth: false,
    });

    expect(next.phase).toBe("needs_password");
    expect(next.pendingKeysGenerated).toBe(true);
    expect(next.devicePublicKeys?.hybridSigningPublicKeyMaterial.owner_id).toBe("device-1");
  });

  it("moves approval into reauth with the pending public keys", () => {
    const publicKeys = makePublicKeys("device-2", new Uint8Array([4]));

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
      publicKeys: makePublicKeys("device-3", new Uint8Array([7])),
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
        publicKeys: makePublicKeys("device-4", new Uint8Array([10])),
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
