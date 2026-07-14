import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import {
  handleClearPluginApplicationDataWithDsk,
  handleDeleteGuestPendingKeysWithDsk,
  handleGenerateDskKey,
  handlePersistCurrentKeysWithDsk,
  handlePersistGuestPendingKeysWithDsk,
  handleRestoreGuestPendingKeysWithDsk,
  pluginApplicationStorageKeyPrefixes,
  pluginCredentialStorageKey,
} from "./dsk";
import { createInitialState } from "../../state";
import { handleGenerateDeviceKeys, handleGenerateUmk } from "./material";

const dskIdb = vi.hoisted(() => ({
  deleteByPrefix: vi.fn(),
  deleteValue: vi.fn(),
  loadValue: vi.fn(),
  storeValue: vi.fn(),
}));

vi.mock("../dsk-idb", () => ({
  SHARE_PARTICIPANT_DEVICE_KEY_PREFIX: "wrapped-share-participant-device",
  deleteDskStoreValuesByPrefixInWorker: dskIdb.deleteByPrefix,
  deleteDskStoreValueInWorker: dskIdb.deleteValue,
  loadDskStoreValueInWorker: dskIdb.loadValue,
  loadShareParticipantDeviceKeysInWorker: vi.fn(),
  storeDskInWorker: vi.fn(),
  storeDskStoreValueInWorker: dskIdb.storeValue,
  storeShareParticipantDeviceKeysInWorker: vi.fn(),
}));

describe("DSK plugin credential storage", () => {
  beforeEach(() => {
    dskIdb.deleteByPrefix.mockReset();
    dskIdb.deleteValue.mockReset();
    dskIdb.loadValue.mockReset();
    dskIdb.storeValue.mockReset();
  });

  it("uses the Host credential namespace required for persisted credentials", () => {
    expect(
      pluginCredentialStorageKey({
        workspaceId: "workspace-one",
        packageId: "package-one",
        applicationId: "application-one",
        activationId: "activation-one",
        userId: "user-one",
        deviceId: "device-one",
        credentialId: "github",
      }),
    ).toBe(
      "refmd-plugin-credential:package-one:application-one:activation-one:workspace-one:user-one:device-one:github",
    );
  });

  it("uses the same application namespace for local data cleanup prefixes", () => {
    expect(
      pluginApplicationStorageKeyPrefixes({
        workspaceId: "workspace-one",
        packageId: "package-one",
        applicationId: "application-one",
        activationId: "activation-one",
        userId: "user-one",
        deviceId: "device-one",
      }),
    ).toEqual({
      userLocal:
        "refmd-plugin-user-local:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
      cache:
        "refmd-plugin-cache:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
      credential:
        "refmd-plugin-credential:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
    });
  });

  it("clears persisted local data with exact application namespace prefixes", async () => {
    await handleClearPluginApplicationDataWithDsk({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      userId: "user-one",
      deviceId: "device-one",
    });

    expect(
      dskIdb.deleteByPrefix.mock.calls.map(([prefix]) => prefix).sort((a, b) => a.localeCompare(b)),
    ).toEqual(
      [
        "refmd-plugin-cache:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
        "refmd-plugin-credential:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
        "refmd-plugin-user-local:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
      ].sort(),
    );
  });
});

describe("DSK KMSI persistence", () => {
  beforeEach(() => {
    dskIdb.deleteByPrefix.mockReset();
    dskIdb.deleteValue.mockReset();
    dskIdb.loadValue.mockReset();
    dskIdb.storeValue.mockReset();
  });

  it("removes an existing wrapped UMK when KMSI persistence is disabled", async () => {
    await handlePersistCurrentKeysWithDsk(createInitialState(), {
      userId: "user-one",
      persistUmk: false,
    });

    expect(dskIdb.deleteValue).toHaveBeenCalledWith("wrapped-umk");
    expect(dskIdb.storeValue).not.toHaveBeenCalledWith("wrapped-umk", expect.anything());
  });

  it("keeps pending guest keys in a namespaced slot and restores them independently", async () => {
    const pendingState = createInitialState();
    await handleGenerateDskKey(pendingState);
    handleGenerateUmk(pendingState);
    const device = handleGenerateDeviceKeys(pendingState, {
      deviceId: "guest-device-one",
    }) as { signingKeyId: string };

    await handlePersistGuestPendingKeysWithDsk(pendingState, {
      storageKey: "lookup-token-one",
      userId: "guest-user-one",
    });

    expect(dskIdb.storeValue).toHaveBeenCalledTimes(1);
    expect(dskIdb.storeValue).toHaveBeenCalledWith(
      "guest-pending-keys:lookup-token-one",
      expect.objectContaining({
        wrappedUmk: expect.any(Object),
        wrappedDevice: expect.any(Object),
      }),
    );
    expect(dskIdb.storeValue).not.toHaveBeenCalledWith("wrapped-umk", expect.anything());
    expect(dskIdb.storeValue).not.toHaveBeenCalledWith("wrapped-device-ecdh", expect.anything());

    const stored = structuredClone(dskIdb.storeValue.mock.calls[0]?.[1]);
    dskIdb.loadValue.mockResolvedValueOnce(stored);
    const restoredState = createInitialState();
    restoredState.dsk = pendingState.dsk;
    restoredState.userId = "guest-user-one";
    restoredState.deviceId = "guest-device-one";
    await expect(
      handleRestoreGuestPendingKeysWithDsk(restoredState, {
        storageKey: "lookup-token-one",
        userId: "guest-user-one",
        signingKeyId: device.signingKeyId,
      }),
    ).resolves.toEqual({ restored: true });
    expect(restoredState.umk).not.toBeNull();
    expect(restoredState.deviceId).toBe("guest-device-one");

    await handleDeleteGuestPendingKeysWithDsk({ storageKey: "lookup-token-one" });
    expect(dskIdb.deleteValue).toHaveBeenCalledWith("guest-pending-keys:lookup-token-one");
  });
});
