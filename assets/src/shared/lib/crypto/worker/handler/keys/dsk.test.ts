import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import {
  handleClearPluginApplicationDataWithDsk,
  pluginApplicationStorageKeyPrefixes,
  pluginCredentialStorageKey,
} from "./dsk";

const dskIdb = vi.hoisted(() => ({
  deleteByPrefix: vi.fn(),
}));

vi.mock("../dsk-idb", () => ({
  SHARE_PARTICIPANT_DEVICE_KEY_PREFIX: "wrapped-share-participant-device",
  deleteDskStoreValuesByPrefixInWorker: dskIdb.deleteByPrefix,
  deleteDskStoreValueInWorker: vi.fn(),
  loadDskStoreValueInWorker: vi.fn(),
  loadShareParticipantDeviceKeysInWorker: vi.fn(),
  storeDskInWorker: vi.fn(),
  storeDskStoreValueInWorker: vi.fn(),
  storeShareParticipantDeviceKeysInWorker: vi.fn(),
}));

describe("DSK plugin credential storage", () => {
  beforeEach(() => {
    dskIdb.deleteByPrefix.mockReset();
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

    expect(dskIdb.deleteByPrefix.mock.calls.map(([prefix]) => prefix).sort()).toEqual(
      [
        "refmd-plugin-cache:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
        "refmd-plugin-credential:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
        "refmd-plugin-user-local:package-one:application-one:activation-one:workspace-one:user-one:device-one:",
      ].sort(),
    );
  });
});
