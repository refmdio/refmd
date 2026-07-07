import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const deviceMocks = vi.hoisted(() => ({
  generateDeviceKeyPair: vi.fn(),
}));

vi.mock("../../../device", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../device")>();
  return {
    ...actual,
    generateDeviceKeyPair: deviceMocks.generateDeviceKeyPair,
  };
});

import { createInitialState } from "../../state";
import { handleGenerateDeviceKeys } from "./material";

describe("device key material generation", () => {
  beforeEach(() => {
    deviceMocks.generateDeviceKeyPair.mockReset();
  });

  it("leaves existing worker key state unchanged when generated material fails validation", () => {
    const state = createInitialState();
    const previousDevicePrivate = new Uint8Array([1]);
    const previousDevicePublic = new Uint8Array([2]);
    const previousEncryptionPrivate = { owner_kind: "device", owner_id: "old-device" };
    const previousEncryptionPublic = { owner_kind: "device", owner_id: "old-device" };
    const previousDeviceSigningState = {
      privateKeyMaterial: { owner_kind: "device", owner_id: "old-device" },
      publicKeyMaterial: { owner_kind: "device", owner_id: "old-device" },
      signingKeyId: "old-signing-key",
    };

    state.deviceId = "old-device";
    state.deviceEcdhPrivate = previousDevicePrivate;
    state.deviceEcdhPublic = previousDevicePublic;
    state.deviceHybridEncryptionPrivateKeyMaterial = previousEncryptionPrivate as never;
    state.deviceHybridEncryptionPublicKeyMaterial = previousEncryptionPublic as never;
    state.deviceHybridSigningState = previousDeviceSigningState as never;
    state.shareParticipantHybridSigningState = null;

    deviceMocks.generateDeviceKeyPair.mockReturnValue({
      ecdhPrivate: new Uint8Array([9]),
      ecdhPublic: new Uint8Array([8]),
      hybridEncryptionPrivateKeyMaterial: { owner_kind: "device", owner_id: "wrong-device" },
      hybridEncryptionPublicKeyMaterial: { owner_kind: "device", owner_id: "wrong-device" },
      encryptionKeyId: "new-encryption-key",
      hybridSigningPrivateKeyMaterial: { owner_kind: "device", owner_id: "new-device" },
      hybridSigningPublicKeyMaterial: { owner_kind: "device", owner_id: "new-device" },
      signingKeyId: "new-signing-key",
    });

    expect(() => handleGenerateDeviceKeys(state, { deviceId: "new-device" })).toThrow(
      "device_key_owner_mismatch",
    );
    expect(state.deviceId).toBe("old-device");
    expect(state.deviceEcdhPrivate).toBe(previousDevicePrivate);
    expect(state.deviceEcdhPublic).toBe(previousDevicePublic);
    expect(state.deviceHybridEncryptionPrivateKeyMaterial).toBe(previousEncryptionPrivate);
    expect(state.deviceHybridEncryptionPublicKeyMaterial).toBe(previousEncryptionPublic);
    expect(state.deviceHybridSigningState).toBe(previousDeviceSigningState);
    expect(state.shareParticipantHybridSigningState).toBeNull();
  });
});
