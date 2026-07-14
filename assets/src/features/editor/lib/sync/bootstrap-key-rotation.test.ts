import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import * as Y from "yjs";
import {
  acknowledgeDocumentWipeIfRequired,
  completeDekRotationNow,
  completeDekRotationAfterSnapshot,
} from "./bootstrap-key-rotation";
import type { DocumentState } from "../../model/document-state/types";

const mocks = vi.hoisted(() => ({
  acknowledge: vi.fn(),
  buildAppend: vi.fn(),
  buildProof: vi.fn(),
  completeRotation: vi.fn(),
  completedEventHash: vi.fn(),
  deleteOfflineData: vi.fn(),
  decryptTitle: vi.fn(),
  documentsGet: vi.fn(),
  documentsUpdate: vi.fn(),
  encryptTitle: vi.fn(),
  ensureDekCached: vi.fn(),
  evictDek: vi.fn(),
  fetchDirectory: vi.fn(),
  generateDek: vi.fn(),
  getRequirement: vi.fn(),
  initializeDocumentSync: vi.fn(),
  endWipe: vi.fn(),
  notifyLocalEdit: vi.fn(),
  prepareShareRotation: vi.fn(),
  prepareCompletion: vi.fn(),
  reencryptPending: vi.fn(),
  resolveActiveKek: vi.fn(),
  startAppend: vi.fn(),
  unwrapDek: vi.fn(),
  workspacesGet: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  getKekResolverSession: vi.fn(() => ({
    auth: { user: { id: "user-1" } },
    device: { deviceId: "device-1" },
  })),
}));

vi.mock("@/shared/api/encryption", () => ({
  encryptionApi: {
    acknowledgeDocumentWipe: mocks.acknowledge,
    completeDekRotation: mocks.completeRotation,
    createDocumentKey: vi.fn(async () => ({ ok: true })),
    getDocumentWipeRequirement: mocks.getRequirement,
    prepareDekRotationCompletion: mocks.prepareCompletion,
  },
}));

vi.mock("@/shared/api/documents", () => ({
  documentsApi: {
    get: mocks.documentsGet,
    update: mocks.documentsUpdate,
  },
}));
vi.mock("@/shared/api/workspaces", () => ({
  workspacesApi: {
    get: mocks.workspacesGet,
    listMembers: vi.fn(async () => ({ members: [{ user_id: "user-1" }] })),
    listMemberDevices: vi.fn(async () => ({ devices: [{ device_id: "device-1" }] })),
  },
}));
vi.mock("@/shared/lib/crypto/kek-resolver", () => ({
  resolveActiveKek: mocks.resolveActiveKek,
}));
vi.mock("@/shared/lib/crypto/share-key-rotation", () => ({
  prepareDocumentShareKeyRotation: mocks.prepareShareRotation,
}));
vi.mock("@/shared/lib/crypto/key-directory/rotation-events", () => ({
  buildDekOldKeyDeletionManifestHash: vi.fn(() => "deletion-manifest-hash"),
  buildDekRotationCompletionKeyDirectoryAppend: mocks.buildAppend,
  buildDekRotationStartKeyDirectoryAppend: mocks.startAppend,
  dekRotationCompletedEventHash: mocks.completedEventHash,
}));
vi.mock("@/shared/lib/crypto/device-key-deletion-proof", () => ({
  buildCurrentDeviceKeyDeletionProof: mocks.buildProof,
  deletedKeySecretIdsHash: vi.fn(() => "deleted-secret-ids-hash"),
}));
vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: vi.fn(() => ({
    decryptTitle: mocks.decryptTitle,
    encryptTitle: mocks.encryptTitle,
    evictDek: mocks.evictDek,
    generateDek: mocks.generateDek,
    unwrapDek: mocks.unwrapDek,
  })),
}));
vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchDirectory,
}));
vi.mock("@/shared/lib/offline/storage/store", () => ({
  deleteDocumentOfflineData: mocks.deleteOfflineData,
}));
vi.mock("@/shared/lib/crypto/document-key-write-barrier", () => ({
  beginDocumentOfflineWipe: vi.fn(async () => mocks.endWipe),
}));
vi.mock("./initialize", () => ({
  initializeDocumentSync: mocks.initializeDocumentSync,
}));
vi.mock("../offline/pending-reencrypt", () => ({
  reencryptPendingChangesForLatestDek: mocks.reencryptPending,
}));
vi.mock("./inbound-verify-decrypt", () => ({
  ensureDekCached: mocks.ensureDekCached,
}));

describe("completeDekRotationNow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.workspacesGet.mockResolvedValue({ needs_kek_rotation: false });
    mocks.fetchDirectory.mockResolvedValue({ checkpoint: { payload: {} } });
    mocks.startAppend.mockResolvedValue({
      events: [{ payload: { event_type: "rotation_started" } }],
      checkpoint: { payload: { sequence: 2 } },
    });
    mocks.prepareShareRotation.mockResolvedValue({});
    mocks.generateDek.mockResolvedValue({
      encryptedDek: new Uint8Array([1]),
      nonce: new Uint8Array([2]),
      keyVersion: 1,
    });
    mocks.decryptTitle.mockResolvedValue("Encrypted title");
    mocks.encryptTitle.mockResolvedValue({
      encrypted: new Uint8Array([3]),
      nonce: new Uint8Array([4]),
    });
    mocks.documentsUpdate.mockResolvedValue({});
  });

  it("reacquires the old DEK and signs the authoritative rotation reason", async () => {
    mocks.documentsGet.mockResolvedValue({
      needs_dek_rotation: true,
      needs_rotation_snapshot: false,
      dek_rotation_reason: "security",
      min_dek_version: 1,
      encrypted_title: null,
      encrypted_title_nonce: null,
      encrypted_title_key_version: null,
    });
    const state = rotationState();

    await completeDekRotationNow("document-1", "workspace-1", state);

    expect(mocks.ensureDekCached).toHaveBeenCalledWith("document-1", "workspace-1", 1, state);
    expect(mocks.startAppend).toHaveBeenCalledWith(expect.objectContaining({ reason: "security" }));
    expect(state.pendingRotationKeyVersion).toBe(2);
    expect(state.pendingRotationSnapshot).toBe(true);
  });

  it("retries stale title encryption before resuming a pending rotation snapshot", async () => {
    const doc = pendingSnapshotDocument();
    mocks.documentsGet.mockResolvedValue(doc);
    const state = rotationState();

    await completeDekRotationNow("document-1", "workspace-1", state);

    expect(mocks.ensureDekCached).toHaveBeenCalledWith("document-1", "workspace-1", 1, state);
    expect(mocks.documentsUpdate).toHaveBeenCalledWith(
      "document-1",
      expect.objectContaining({ encrypted_title_key_version: 2 }),
    );
    expect(state.pendingRotationKeyVersion).toBe(2);
    expect(state.pendingRotationSnapshot).toBe(true);
  });

  it("does not advance snapshot completion when title encryption still fails", async () => {
    mocks.documentsGet.mockResolvedValue(pendingSnapshotDocument());
    mocks.documentsUpdate.mockRejectedValueOnce(new Error("title_update_failed"));
    const state = rotationState();

    await expect(completeDekRotationNow("document-1", "workspace-1", state)).rejects.toThrow(
      "title_update_failed",
    );

    expect(state.pendingRotationSnapshot).toBe(false);
    expect(mocks.notifyLocalEdit).not.toHaveBeenCalled();
  });

  it("does not advance snapshot completion when title metadata refresh fails", async () => {
    mocks.documentsGet
      .mockResolvedValueOnce({
        needs_dek_rotation: true,
        needs_rotation_snapshot: false,
        dek_rotation_reason: "security",
        min_dek_version: 1,
        encrypted_title: null,
        encrypted_title_nonce: null,
        encrypted_title_key_version: null,
      })
      .mockRejectedValueOnce(new Error("title_metadata_unavailable"));
    const state = rotationState();

    await expect(completeDekRotationNow("document-1", "workspace-1", state)).rejects.toThrow(
      "title_metadata_unavailable",
    );

    expect(state.pendingRotationSnapshot).toBe(false);
    expect(mocks.notifyLocalEdit).not.toHaveBeenCalled();
  });
});

describe("completeDekRotationAfterSnapshot", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.fetchDirectory.mockResolvedValue({ checkpoint: { payload: {} } });
    mocks.prepareCompletion.mockResolvedValue({
      old_key_version: 1,
      new_key_version: 2,
      completion_manifest_hash: "completion-manifest-hash",
      deleted_wrap_ids_hash: "deleted-wrap-ids-hash",
      server_rejects_old_key_uploads_after_sequence: 4,
    });
    mocks.completedEventHash.mockReturnValue("rotation-completed-hash");
    mocks.buildProof.mockResolvedValue({ payload: { device_id: "device-1" } });
    mocks.buildAppend.mockResolvedValue({
      events: [{ payload: { event_type: "rotation_completed" } }],
      checkpoint: { payload: { sequence: 4 } },
    });
    mocks.completeRotation.mockResolvedValue({ ok: true });
  });

  it("covers every active device by wipe without signing an initiator proof", async () => {
    const state = wipeState();
    await completeDekRotationAfterSnapshot({
      documentId: "document-1",
      workspaceId: "workspace-1",
      oldKeyVersion: 1,
      newKeyVersion: 2,
      state,
    });

    expect(mocks.evictDek).not.toHaveBeenCalled();
    expect(mocks.deleteOfflineData).not.toHaveBeenCalled();
    expect(mocks.buildProof).not.toHaveBeenCalled();
    expect(mocks.completeRotation).toHaveBeenCalledWith("document-1", {
      new_key_version: 2,
      workspace_key_directory_events: [{ payload: { event_type: "rotation_completed" } }],
      workspace_key_directory_checkpoint: { payload: { sequence: 4 } },
      device_key_deletion_proofs: [],
      wipe_required_device_ids: ["device-1"],
    });
  });

  it("propagates completion failure without claiming local deletion", async () => {
    mocks.completeRotation.mockRejectedValueOnce(new Error("completion_failed"));

    await expect(
      completeDekRotationAfterSnapshot({
        documentId: "document-1",
        workspaceId: "workspace-1",
        oldKeyVersion: 1,
        newKeyVersion: 2,
        state: wipeState(),
      }),
    ).rejects.toThrow("completion_failed");
    expect(mocks.buildProof).not.toHaveBeenCalled();
    expect(mocks.deleteOfflineData).not.toHaveBeenCalled();
  });
});

describe("acknowledgeDocumentWipeIfRequired", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getRequirement
      .mockReset()
      .mockResolvedValueOnce(documentRequirement(1, 2))
      .mockResolvedValueOnce(null);
    mocks.fetchDirectory.mockResolvedValue({ checkpoint: { payload: {} } });
    mocks.buildProof.mockResolvedValue({ payload: { device_id: "device-1" } });
    mocks.acknowledge.mockResolvedValue({ ok: true });
    mocks.initializeDocumentSync.mockImplementation(async (_documentId, _workspaceId, state) => {
      state.initialized = true;
    });
  });

  it("deletes old local state before signing and acknowledging the wipe", async () => {
    const state = wipeState();
    await acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state);

    expect(mocks.evictDek).toHaveBeenCalledWith("document-1", 1);
    expect(mocks.deleteOfflineData).toHaveBeenCalledWith("document-1");
    expect(mocks.buildProof).toHaveBeenCalledOnce();
    expect(mocks.acknowledge).toHaveBeenCalledOnce();
    expect(mocks.deleteOfflineData.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.buildProof.mock.invocationCallOrder[0]!,
    );
    expect(mocks.buildProof.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.acknowledge.mock.invocationCallOrder[0]!,
    );
    expect(state.yDoc.getText("content").toJSON()).toBe("");
    expect(state.lastSavedState).toBeNull();
    expect(state.loadedFromOfflineCache).toBe(false);
  });

  it("does not acknowledge when local deletion fails", async () => {
    const state = wipeState();
    mocks.getRequirement
      .mockReset()
      .mockResolvedValueOnce(documentRequirement(1, 2))
      .mockResolvedValueOnce(documentRequirement(1, 2))
      .mockResolvedValueOnce(null);
    mocks.deleteOfflineData.mockRejectedValueOnce(new Error("delete_failed"));

    await expect(
      acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state),
    ).rejects.toThrow("delete_failed");
    expect(mocks.buildProof).not.toHaveBeenCalled();
    expect(mocks.acknowledge).not.toHaveBeenCalled();

    await expect(
      acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state),
    ).resolves.toBe(true);

    expect(mocks.evictDek).toHaveBeenCalledTimes(2);
    expect(mocks.deleteOfflineData).toHaveBeenCalledTimes(2);
    expect(mocks.buildProof).toHaveBeenCalledOnce();
    expect(mocks.acknowledge).toHaveBeenCalledOnce();
    expect(mocks.endWipe).toHaveBeenCalledOnce();
  });

  it("releases the wipe barrier after acknowledgement and before reinitializing", async () => {
    const state = wipeState();
    state.initialized = true;

    await acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state);

    expect(mocks.initializeDocumentSync).toHaveBeenCalledWith("document-1", "workspace-1", state, {
      skipDocumentWipeAcknowledgement: true,
    });
    expect(mocks.acknowledge.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.endWipe.mock.invocationCallOrder[0]!,
    );
    expect(mocks.endWipe.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.initializeDocumentSync.mock.invocationCallOrder[0]!,
    );
    expect(state.initialized).toBe(true);
    expect(state._syncPaused).toBe(false);
  });

  it("keeps synchronization paused when open-editor reinitialization fails", async () => {
    const state = wipeState();
    state.initialized = true;
    mocks.initializeDocumentSync.mockRejectedValueOnce(new Error("reinitialize_failed"));

    await expect(
      acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state),
    ).rejects.toThrow("reinitialize_failed");

    expect(mocks.endWipe).toHaveBeenCalledOnce();
    expect(state._syncPaused).toBe(true);
  });

  it("coalesces concurrent wipe acknowledgement for the same editor state", async () => {
    const state = wipeState();
    state.initialized = true;

    await Promise.all([
      acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state),
      acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state),
    ]);

    expect(mocks.getRequirement).toHaveBeenCalledTimes(2);
    expect(mocks.acknowledge).toHaveBeenCalledOnce();
    expect(mocks.initializeDocumentSync).toHaveBeenCalledOnce();
  });

  it("recovers when acknowledgement succeeds but its response is lost", async () => {
    const state = wipeState();
    state.initialized = true;
    mocks.acknowledge.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(
      acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state),
    ).rejects.toThrow("Failed to fetch");

    expect(mocks.endWipe).not.toHaveBeenCalled();
    mocks.getRequirement.mockResolvedValueOnce(null);

    await expect(
      acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state),
    ).resolves.toBe(true);

    expect(mocks.deleteOfflineData).toHaveBeenCalledOnce();
    expect(mocks.acknowledge).toHaveBeenCalledOnce();
    expect(mocks.endWipe).toHaveBeenCalledOnce();
    expect(mocks.initializeDocumentSync).toHaveBeenCalledOnce();
  });

  it("keeps external callers waiting while the shared reinitialization is active", async () => {
    const state = wipeState();
    state.initialized = true;
    let finishInitialization!: () => void;
    const initialization = new Promise<void>((resolve) => {
      finishInitialization = resolve;
    });
    mocks.initializeDocumentSync.mockImplementationOnce(async () => {
      await initialization;
      state.initialized = true;
    });

    const first = acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state);
    await vi.waitFor(() => expect(mocks.initializeDocumentSync).toHaveBeenCalledOnce());
    const second = acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state);

    expect(mocks.getRequirement).toHaveBeenCalledTimes(2);
    expect(mocks.acknowledge).toHaveBeenCalledOnce();
    finishInitialization();
    await expect(Promise.all([first, second])).resolves.toEqual([true, true]);
  });

  it("drains every outstanding rotation before reinitializing", async () => {
    const state = wipeState();
    state.initialized = true;
    mocks.getRequirement
      .mockReset()
      .mockResolvedValueOnce(documentRequirement(1, 2))
      .mockResolvedValueOnce(documentRequirement(2, 3))
      .mockResolvedValueOnce(null);

    await acknowledgeDocumentWipeIfRequired("document-1", "workspace-1", state);

    expect(mocks.evictDek.mock.calls).toEqual([
      ["document-1", 1],
      ["document-1", 2],
    ]);
    expect(mocks.acknowledge).toHaveBeenCalledTimes(2);
    expect(mocks.initializeDocumentSync).toHaveBeenCalledOnce();
    expect(mocks.acknowledge.mock.invocationCallOrder[1]).toBeLessThan(
      mocks.initializeDocumentSync.mock.invocationCallOrder[0]!,
    );
  });
});

function rotationState(): DocumentState {
  return {
    access: { kind: "workspace" },
    keyVersion: 1,
    pendingRotationKeyVersion: null,
    pendingRotationSnapshot: false,
    autoSync: { notifyLocalEdit: mocks.notifyLocalEdit },
  } as unknown as DocumentState;
}

function pendingSnapshotDocument() {
  return {
    needs_dek_rotation: false,
    needs_rotation_snapshot: true,
    dek_rotation_reason: null,
    min_dek_version: 2,
    encrypted_title: "encrypted-title",
    encrypted_title_nonce: "title-nonce",
    encrypted_title_key_version: 1,
  };
}

function documentRequirement(oldKeyVersion: number, requiredDekVersion: number) {
  return {
    workspace_id: "workspace-1",
    required_dek_version: requiredDekVersion,
    old_key_version: oldKeyVersion,
    rotation_completed_event_hash: `rotation-hash-${requiredDekVersion}`,
    deleted_secret_ids_hash: `secret-hash-${oldKeyVersion}`,
  };
}

function wipeState(): DocumentState {
  const yDoc = new Y.Doc();
  yDoc.getText("content").insert(0, "offline text");
  return {
    stateKey: "document-1",
    documentId: "document-1",
    yDoc,
    autoSync: null,
    offlineFlushCleanup: null,
    offlineResumeCleanup: null,
    writerLockCleanup: null,
    _reconnectTimer: null,
    _syncGapTimer: null,
    pendingSaveTimeout: null,
    verifiedWriteSessions: new Map(),
    pendingVerifiedWriteSessions: new Map(),
    knownClocks: {},
    confirmedClocks: {},
    writeSessionCounters: {},
    snapshotBaseClocks: {},
    _pendingRemoteEvents: [],
    _pendingOutOfOrderUpdates: [],
    lastSavedState: new Uint8Array([1]),
    pendingUpdateBytes: new Uint8Array([2]),
    pendingUpdateEnvelope: {},
    pendingSnapshot: {},
    pendingSnapshotEnvelope: {},
    loadedFromOfflineCache: true,
  } as unknown as DocumentState;
}
