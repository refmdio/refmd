import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import {
  handleClearPluginApplicationDataWithDsk,
  handlePersistCurrentKeysWithDsk,
  pluginApplicationStorageKeyPrefixes,
  pluginCredentialStorageKey,
} from "./dsk";
import { createInitialState } from "../../state";

const dskIdb = vi.hoisted(() => ({
  deleteByPrefix: vi.fn(),
  deleteValue: vi.fn(),
  storeValue: vi.fn(),
}));

vi.mock("../dsk-idb", () => ({
  SHARE_PARTICIPANT_DEVICE_KEY_PREFIX: "wrapped-share-participant-device",
  deleteDskStoreValuesByPrefixInWorker: dskIdb.deleteByPrefix,
  deleteDskStoreValueInWorker: dskIdb.deleteValue,
  loadDskStoreValueInWorker: vi.fn(),
  loadShareParticipantDeviceKeysInWorker: vi.fn(),
  storeDskInWorker: vi.fn(),
  storeDskStoreValueInWorker: dskIdb.storeValue,
  storeShareParticipantDeviceKeysInWorker: vi.fn(),
}));

describe("DSK plugin credential storage", () => {
  beforeEach(() => {
    dskIdb.deleteByPrefix.mockReset();
    dskIdb.deleteValue.mockReset();
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
});
