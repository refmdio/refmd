import { beforeEach, expect, it, vi } from "vite-plus/test";
import { acknowledgeWorkspaceWipeIfRequired } from "./workspace-kek-wipe";

const mocks = vi.hoisted(() => ({
  acknowledge: vi.fn(),
  buildProof: vi.fn(),
  deleteDocument: vi.fn(),
  deleteKek: vi.fn(),
  deleteOfflineCreated: vi.fn(),
  deleteOfflineKek: vi.fn(),
  evictDek: vi.fn(),
  fetchDirectory: vi.fn(),
  getRequirement: vi.fn(),
  setActiveKekVersion: vi.fn(),
}));

vi.mock("@/shared/api/encryption", () => ({
  encryptionApi: {
    acknowledgeWorkspaceWipe: mocks.acknowledge,
    getWorkspaceWipeRequirement: mocks.getRequirement,
  },
}));
vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchDirectory,
}));
vi.mock("@/shared/lib/offline/storage/store", () => ({
  deleteDocumentOfflineData: mocks.deleteDocument,
  deleteOfflineCreated: mocks.deleteOfflineCreated,
  deleteOfflineKek: mocks.deleteOfflineKek,
  getAllOfflineCreated: vi.fn(async () => []),
  getAllOfflineDocumentMetas: vi.fn(async () => [
    { documentId: "document-1", workspaceId: "workspace-1" },
  ]),
  getDocumentCache: vi.fn(async () => ({ keyVersion: 3 })),
  getOfflineDocumentIndex: vi.fn(async () => []),
  getPendingChanges: vi.fn(async () => ({ keyVersion: 2 })),
}));
vi.mock("./worker/client", () => ({
  getCryptoWorker: vi.fn(() => ({
    deleteKekVersion: mocks.deleteKek,
    evictDek: mocks.evictDek,
    setActiveKekVersion: mocks.setActiveKekVersion,
  })),
}));
vi.mock("./device-key-deletion-proof", () => ({
  buildCurrentDeviceKeyDeletionProof: mocks.buildProof,
}));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.getRequirement
    .mockReset()
    .mockResolvedValueOnce(workspaceRequirement(1, 2))
    .mockResolvedValueOnce(null);
  mocks.fetchDirectory.mockResolvedValue({ checkpoint: { payload: {} } });
  mocks.buildProof.mockResolvedValue({ payload: { device_id: "device-1" } });
});

it("deletes workspace state before signing and acknowledging", async () => {
  await acknowledgeWorkspaceWipeIfRequired({
    workspaceId: "workspace-1",
    userId: "user-1",
    deviceId: "device-1",
  });

  expect(mocks.evictDek).toHaveBeenCalledTimes(2);
  expect(mocks.deleteDocument).toHaveBeenCalledWith("document-1");
  expect(mocks.setActiveKekVersion).toHaveBeenCalledWith("workspace-1", 2);
  expect(mocks.setActiveKekVersion.mock.invocationCallOrder[0]).toBeLessThan(
    mocks.deleteKek.mock.invocationCallOrder[0]!,
  );
  expect(mocks.deleteKek).toHaveBeenCalledWith("workspace-1", 1);
  expect(mocks.deleteOfflineKek).toHaveBeenCalledWith("workspace-1");
  expect(mocks.deleteOfflineKek.mock.invocationCallOrder[0]).toBeLessThan(
    mocks.buildProof.mock.invocationCallOrder[0]!,
  );
  expect(mocks.buildProof.mock.invocationCallOrder[0]).toBeLessThan(
    mocks.acknowledge.mock.invocationCallOrder[0]!,
  );
});

it("does not sign or acknowledge when deletion fails", async () => {
  mocks.deleteDocument.mockRejectedValueOnce(new Error("delete_failed"));

  await expect(
    acknowledgeWorkspaceWipeIfRequired({
      workspaceId: "workspace-1",
      userId: "user-1",
      deviceId: "device-1",
    }),
  ).rejects.toThrow("delete_failed");
  expect(mocks.buildProof).not.toHaveBeenCalled();
  expect(mocks.acknowledge).not.toHaveBeenCalled();
});

it("coalesces concurrent destructive acknowledgement", async () => {
  let release!: () => void;
  mocks.acknowledge.mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
      }),
  );

  const params = {
    workspaceId: "workspace-1",
    userId: "user-1",
    deviceId: "device-1",
  };
  const first = acknowledgeWorkspaceWipeIfRequired(params);
  await vi.waitFor(() => expect(mocks.acknowledge).toHaveBeenCalledOnce());
  const second = acknowledgeWorkspaceWipeIfRequired(params);
  release();
  await Promise.all([first, second]);

  expect(mocks.getRequirement).toHaveBeenCalledTimes(2);
  expect(mocks.deleteDocument).toHaveBeenCalledOnce();
  expect(mocks.acknowledge).toHaveBeenCalledOnce();
});

it("retries after an acknowledgement failure", async () => {
  mocks.getRequirement
    .mockReset()
    .mockResolvedValueOnce(workspaceRequirement(1, 2))
    .mockResolvedValueOnce(workspaceRequirement(1, 2))
    .mockResolvedValueOnce(null);
  mocks.acknowledge
    .mockRejectedValueOnce(new Error("acknowledgement_unavailable"))
    .mockResolvedValueOnce(undefined);
  const params = {
    workspaceId: "workspace-1",
    userId: "user-1",
    deviceId: "device-1",
  };

  await expect(acknowledgeWorkspaceWipeIfRequired(params)).rejects.toThrow(
    "acknowledgement_unavailable",
  );
  await expect(acknowledgeWorkspaceWipeIfRequired(params)).resolves.toBeUndefined();

  expect(mocks.getRequirement).toHaveBeenCalledTimes(3);
  expect(mocks.acknowledge).toHaveBeenCalledTimes(2);
});

it("drains every outstanding rotation in key-version order", async () => {
  mocks.getRequirement
    .mockReset()
    .mockResolvedValueOnce(workspaceRequirement(1, 2))
    .mockResolvedValueOnce(workspaceRequirement(2, 3))
    .mockResolvedValueOnce(null);

  await acknowledgeWorkspaceWipeIfRequired({
    workspaceId: "workspace-1",
    userId: "user-1",
    deviceId: "device-1",
  });

  expect(mocks.setActiveKekVersion.mock.calls).toEqual([
    ["workspace-1", 2],
    ["workspace-1", 3],
  ]);
  expect(mocks.deleteKek.mock.calls).toEqual([
    ["workspace-1", 1],
    ["workspace-1", 2],
  ]);
  expect(mocks.acknowledge).toHaveBeenCalledTimes(2);
});

function workspaceRequirement(oldKeyVersion: number, requiredKekVersion: number) {
  return {
    workspace_id: "workspace-1",
    required_kek_version: requiredKekVersion,
    old_key_version: oldKeyVersion,
    rotation_completed_event_hash: `rotation-hash-${requiredKekVersion}`,
    deleted_secret_ids_hash: `secret-hash-${oldKeyVersion}`,
  };
}
