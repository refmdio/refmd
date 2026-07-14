import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  buildKekOldKeyDeletionManifestHash: vi.fn(),
  buildKekRotationCompletionKeyDirectoryAppend: vi.fn(),
  getWorkspaceIds: vi.fn(),
  listDocuments: vi.fn(),
  getDocumentKeys: vi.fn(),
  rewrapDocumentKeyForKekRotation: vi.fn(),
  getWorkspaceMemberKeys: vi.fn(),
  prepareKekRotationCompletion: vi.fn(),
  completeKekRotation: vi.fn(),
  startKekRotation: vi.fn(),
  generateKek: vi.fn(),
  resolveKek: vi.fn(),
  resolveKekByVersion: vi.fn(),
  loadOfflineKekMetadata: vi.fn(),
  setActiveKekVersion: vi.fn(),
  restoreKekFromOffline: vi.fn(),
  storeKekForOffline: vi.fn(),
  deleteKekVersion: vi.fn(),
  unwrapDek: vi.fn(),
  wrapDek: vi.fn(),
  list: vi.fn(),
  listMembers: vi.fn(),
  listMemberDevices: vi.fn(),
  revoke: vi.fn(),
  createDeviceRevocationSignature: vi.fn(),
  kekRotationCompletedEventHash: vi.fn(),
  buildKekRotationStartKeyDirectoryAppend: vi.fn(),
  persistWorkspaceKekForDevice: vi.fn(),
  persistWorkspaceKekForMember: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  buildDeviceRevocationKeyDirectoryAppend: vi.fn(),
  advanceKeyDirectoryPinWithProof: vi.fn(),
  acknowledgeWorkspaceWipeIfRequired: vi.fn(),
  signDeviceKeyDeletionProof: vi.fn(),
  tofuVerify: vi.fn(),
  tofuUpdateLastSeen: vi.fn(),
  verifyDeviceApprovalSignature: vi.fn(),
  verifyGenesisDeviceBootstrapSignature: vi.fn(),
  verifyRecoveryDeviceApprovalSignature: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    code: string | null;

    constructor(status: number, body: Record<string, unknown>) {
      super(`API error ${status}`);
      this.status = status;
      this.code = typeof body.error === "string" ? body.error : null;
    }
  },
  devicesApi: {
    list: mocks.list,
    revoke: mocks.revoke,
  },
  encryptionApi: {
    getWorkspaceIds: mocks.getWorkspaceIds,
    getWorkspaceMemberKeys: mocks.getWorkspaceMemberKeys,
    prepareKekRotationCompletion: mocks.prepareKekRotationCompletion,
    completeKekRotation: mocks.completeKekRotation,
    startKekRotation: mocks.startKekRotation,
    getDocumentKeys: mocks.getDocumentKeys,
    rewrapDocumentKeyForKekRotation: mocks.rewrapDocumentKeyForKekRotation,
  },
  documentsApi: { list: mocks.listDocuments },
  workspacesApi: {
    listMembers: mocks.listMembers,
    listMemberDevices: mocks.listMemberDevices,
  },
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/crypto/key-directory/membership-events", () => ({
  buildDeviceRevocationKeyDirectoryAppend: mocks.buildDeviceRevocationKeyDirectoryAppend,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advanceKeyDirectoryPinWithProof,
}));

vi.mock("@/shared/lib/crypto/workspace-kek-wipe", () => ({
  acknowledgeWorkspaceWipeIfRequired: mocks.acknowledgeWorkspaceWipeIfRequired,
}));

vi.mock("@/shared/lib/crypto/kek-resolver", () => ({
  resolveKekByVersion: mocks.resolveKekByVersion,
}));

vi.mock("@/shared/lib/crypto/workspace-kek-persistence", () => ({
  persistWorkspaceKekForDevice: mocks.persistWorkspaceKekForDevice,
  persistWorkspaceKekForMember: mocks.persistWorkspaceKekForMember,
}));

vi.mock("@/shared/lib/crypto/key-directory/rotation-events", () => ({
  buildKekOldKeyDeletionManifestHash: mocks.buildKekOldKeyDeletionManifestHash,
  buildKekRotationCompletionKeyDirectoryAppend: mocks.buildKekRotationCompletionKeyDirectoryAppend,
  buildKekRotationStartKeyDirectoryAppend: mocks.buildKekRotationStartKeyDirectoryAppend,
  kekRotationCompletedEventHash: mocks.kekRotationCompletedEventHash,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    createDeviceRevocationSignature: mocks.createDeviceRevocationSignature,
    generateKek: mocks.generateKek,
    resolveKek: mocks.resolveKek,
    loadOfflineKekMetadata: mocks.loadOfflineKekMetadata,
    setActiveKekVersion: mocks.setActiveKekVersion,
    restoreKekFromOffline: mocks.restoreKekFromOffline,
    storeKekForOffline: mocks.storeKekForOffline,
    deleteKekVersion: mocks.deleteKekVersion,
    unwrapDek: mocks.unwrapDek,
    wrapDek: mocks.wrapDek,
    signDeviceKeyDeletionProof: mocks.signDeviceKeyDeletionProof,
    tofuVerify: mocks.tofuVerify,
    tofuUpdateLastSeen: mocks.tofuUpdateLastSeen,
    verifyDeviceApprovalSignature: mocks.verifyDeviceApprovalSignature,
    verifyGenesisDeviceBootstrapSignature: mocks.verifyGenesisDeviceBootstrapSignature,
    verifyRecoveryDeviceApprovalSignature: mocks.verifyRecoveryDeviceApprovalSignature,
  }),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  cryptoWorkerReady: mocks.cryptoWorkerReady,
  deviceState: mocks.deviceState,
  getKekResolverSession: vi.fn(() => ({ auth: {}, device: {} })),
}));

import { ApiError } from "@/shared/api";
import { revokeDevice } from "./revoke";

const deviceHybridSigningPublicKeyMaterial = {
  protocol: "refmd.hybrid-signing-key-material",
  owner_kind: "device",
  owner_id: "device_current",
  ed25519_public: "AA",
  mldsa65_public: "AA",
};

const deviceHybridEncryptionPublicKeyMaterial = {
  protocol: "refmd.hybrid-encryption-key-material",
  owner_kind: "device",
  owner_id: "device_current",
  x25519_public: "AA",
  mlkem768_public: "AA",
};

const currentDevice = {
  id: "device_current",
  name: "Current device",
  signing_key_id: "signing_key_current",
  encryption_key_id: "encryption_key_current",
  hybrid_signing_public_key_material: deviceHybridSigningPublicKeyMaterial,
  hybrid_encryption_public_key_material: deviceHybridEncryptionPublicKeyMaterial,
  approval_signature: { signature: "identity-signature" },
  approval_signature_surface: "genesis_device_bootstrap",
  approval_proof: { proof: "identity" },
  approval_delivery_commitments: { commitments: [] },
  approval_delivery_artifacts: { artifacts: [] },
  client_nonce: "AA",
};

const targetDevice = {
  id: "device_target",
  name: "Target device",
  signing_key_id: "signing_key_target",
  encryption_key_id: "encryption_key_target",
  hybrid_signing_public_key_material: {
    ...deviceHybridSigningPublicKeyMaterial,
    owner_id: "device_target",
  },
  hybrid_encryption_public_key_material: {
    ...deviceHybridEncryptionPublicKeyMaterial,
    owner_id: "device_target",
  },
  approval_signature: { signature: "target-identity-signature" },
  approval_signature_surface: "device_approval",
  approval_proof: { proof: "target-identity" },
  approval_delivery_commitments: { commitments: [] },
  approval_delivery_artifacts: { artifacts: [] },
  client_nonce: "AA",
};

const workspaceCheckpoint = {
  payload: {
    sequence: 1,
    device_keys: [
      {
        key_id: "signing_key_current",
        key_material: deviceHybridSigningPublicKeyMaterial,
      },
      {
        key_id: "encryption_key_current",
        key_material: deviceHybridEncryptionPublicKeyMaterial,
      },
    ],
  },
};

describe("revoke", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "user_1" } });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.deviceState.mockReturnValue({ deviceId: "device_current" });
    mocks.createDeviceRevocationSignature.mockResolvedValue({
      signature: {
        protocol: "refmd.hybrid-signature",
        version: 1,
        suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
        suite_rank: 1000,
        signing_key_id: "signing_key_current",
        transcript_hash: "hash",
        ed25519: "ed25519",
        mldsa65: "mldsa65",
      },
    });
    mocks.list.mockImplementation((opts?: { rrpDeviceId?: string }) =>
      Promise.resolve({ devices: opts?.rrpDeviceId ? [targetDevice] : [currentDevice] }),
    );
    mocks.getWorkspaceIds.mockResolvedValue({ workspace_ids: ["workspace_1"] });
    mocks.fetchVerifiedKeyDirectory.mockImplementation(({ scopeKind }: { scopeKind: string }) =>
      Promise.resolve({
        checkpoint: scopeKind === "workspace" ? workspaceCheckpoint : { payload: { scopeKind } },
      }),
    );
    mocks.buildDeviceRevocationKeyDirectoryAppend.mockResolvedValue({
      events: [{ payload: { event_type: "signing_key_revoked" } }],
      checkpoint: { payload: { sequence: 2 } },
    });
    mocks.advanceKeyDirectoryPinWithProof.mockResolvedValue(undefined);
    mocks.acknowledgeWorkspaceWipeIfRequired.mockResolvedValue(undefined);
    mocks.tofuVerify.mockResolvedValue({ status: "known_trusted" });
    mocks.tofuUpdateLastSeen.mockResolvedValue(undefined);
    mocks.verifyDeviceApprovalSignature.mockResolvedValue(true);
    mocks.verifyGenesisDeviceBootstrapSignature.mockResolvedValue(true);
    mocks.verifyRecoveryDeviceApprovalSignature.mockResolvedValue(true);
    mocks.generateKek.mockResolvedValue(undefined);
    mocks.listDocuments.mockResolvedValue({ documents: [] });
    mocks.getDocumentKeys.mockResolvedValue({ keys: [] });
    mocks.rewrapDocumentKeyForKekRotation.mockResolvedValue(undefined);
    mocks.unwrapDek.mockResolvedValue(undefined);
    mocks.wrapDek.mockResolvedValue({
      encryptedDek: new Uint8Array(48),
      nonce: new Uint8Array(24),
    });
    mocks.deleteKekVersion.mockResolvedValue({
      memoryDeleted: true,
      offlineDeleted: true,
      keyVersion: 1,
    });
    mocks.listMembers.mockResolvedValue({ members: [{ user_id: "user_1" }] });
    mocks.listMemberDevices.mockResolvedValue({
      devices: [{ device_id: "device_current", encryption_key_id: "encryption_key_current" }],
    });
    mocks.persistWorkspaceKekForDevice.mockResolvedValue(undefined);
    mocks.persistWorkspaceKekForMember.mockResolvedValue(undefined);
    mocks.getWorkspaceMemberKeys.mockResolvedValue({
      members: [
        {
          user_id: "user_1",
          hybrid_encryption_public_key_material: {
            ...deviceHybridEncryptionPublicKeyMaterial,
            owner_kind: "identity",
            owner_id: "user_1",
          },
        },
      ],
    });
    mocks.prepareKekRotationCompletion.mockResolvedValue({
      old_kek_version: 1,
      new_kek_version: 2,
      completion_manifest_hash: "completion-manifest-hash",
      deleted_secret_ids_hash: "deleted-secret-ids-hash",
      deleted_wrap_ids_hash: "deleted-wrap-ids-hash",
      server_rejects_old_key_uploads_after_sequence: 2,
    });
    mocks.kekRotationCompletedEventHash.mockReturnValue("rotation-completed-event-hash");
    mocks.signDeviceKeyDeletionProof.mockResolvedValue({
      payload: { protocol: "refmd.device-key-deletion-proof" },
      transcript: { protocol: "refmd.hybrid-signature-transcript" },
      signature: { suite_id: "hybrid-signature-suite" },
    });
    mocks.buildKekOldKeyDeletionManifestHash.mockReturnValue("deletion-manifest-hash");
    mocks.buildKekRotationStartKeyDirectoryAppend.mockResolvedValue({
      events: [{ payload: { event_type: "rotation_started" } }],
      checkpoint: { payload: { sequence: 3 } },
    });
    mocks.buildKekRotationCompletionKeyDirectoryAppend.mockResolvedValue({
      events: [{ payload: { event_type: "rotation_completed" } }],
      checkpoint: { payload: { sequence: 4 } },
    });
    mocks.startKekRotation.mockResolvedValue({
      workspace_id: "workspace_1",
      needs_kek_rotation: true,
    });
    mocks.completeKekRotation.mockResolvedValue(undefined);
    mocks.resolveKek.mockResolvedValue({ found: false });
    mocks.loadOfflineKekMetadata.mockResolvedValue({ keyVersion: 1 });
    mocks.setActiveKekVersion.mockResolvedValue(undefined);
    mocks.restoreKekFromOffline.mockResolvedValue({ restored: false });
    mocks.storeKekForOffline.mockResolvedValue(undefined);
    mocks.revoke.mockResolvedValue({
      revoked_device_id: "device_target",
      revocation_mode: "retire",
      workspaces_needing_kek_rotation: [],
    });
  });

  it("signs and submits hybrid device revocation", async () => {
    const result = await revokeDevice("device_target", "retire");

    expect(result).toEqual({ warning: null });
    expect(mocks.createDeviceRevocationSignature).toHaveBeenCalledWith({
      revokedDeviceId: "device_target",
      revocationMode: "retire",
      revokedAtMs: expect.any(Number),
    });
    expect(mocks.revoke).toHaveBeenCalledWith(
      "device_target",
      "retire",
      {
        protocol: "refmd.hybrid-signature",
        version: 1,
        suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
        suite_rank: 1000,
        signing_key_id: "signing_key_current",
        transcript_hash: "hash",
        ed25519: "ed25519",
        mldsa65: "mldsa65",
      },
      expect.any(Number),
      {
        user_key_directory_events: [{ payload: { event_type: "signing_key_revoked" } }],
        user_key_directory_checkpoint: { payload: { sequence: 2 } },
        workspace_key_directory_appends: [
          {
            workspace_id: "workspace_1",
            events: [{ payload: { event_type: "signing_key_revoked" } }],
            checkpoint: { payload: { sequence: 2 } },
          },
        ],
      },
    );
    expect(mocks.advanceKeyDirectoryPinWithProof).toHaveBeenCalledTimes(2);
  });

  it("completes workspace KEK rotation after security revocation returns affected workspaces", async () => {
    const rotationList = [{ workspace_id: "workspace_1", current_kek_version: 1 }];
    mocks.revoke.mockResolvedValueOnce({
      revoked_device_id: "device_target",
      revocation_mode: "security",
      workspaces_needing_kek_rotation: rotationList,
    });

    const result = await revokeDevice("device_target", "security");

    expect(result).toEqual({ warning: null });
    expect(mocks.revoke).toHaveBeenCalledWith(
      "device_target",
      "security",
      expect.any(Object),
      expect.any(Number),
      expect.any(Object),
    );
    expect(mocks.buildKekRotationStartKeyDirectoryAppend).toHaveBeenCalledWith({
      workspaceId: "workspace_1",
      actorUserId: "user_1",
      actorDeviceId: "device_current",
      checkpointEnvelope: workspaceCheckpoint,
      oldKeyVersion: 1,
      newKeyVersion: 2,
      reason: "security",
    });
    expect(mocks.startKekRotation).toHaveBeenCalledWith("workspace_1", {
      workspace_key_directory_events: [{ payload: { event_type: "rotation_started" } }],
      workspace_key_directory_checkpoint: { payload: { sequence: 3 } },
    });
    expect(mocks.generateKek).toHaveBeenCalledWith("workspace_1", 2);
    expect(mocks.persistWorkspaceKekForDevice).toHaveBeenCalledWith(
      expect.objectContaining({
        workspaceId: "workspace_1",
        keyVersion: 2,
        targetDeviceId: "device_current",
      }),
    );
    expect(mocks.persistWorkspaceKekForMember).toHaveBeenCalledWith(
      expect.objectContaining({
        workspaceId: "workspace_1",
        keyVersion: 2,
        targetUserId: "user_1",
        rrpDeviceId: "device_current",
      }),
    );
    expect(mocks.prepareKekRotationCompletion).toHaveBeenCalledWith("workspace_1", 2);
    expect(mocks.completeKekRotation).toHaveBeenCalledWith("workspace_1", {
      new_kek_version: 2,
      workspace_key_directory_events: [{ payload: { event_type: "rotation_completed" } }],
      workspace_key_directory_checkpoint: { payload: { sequence: 4 } },
      device_key_deletion_proofs: [],
      wipe_required_device_ids: ["device_current"],
    });
    expect(mocks.acknowledgeWorkspaceWipeIfRequired).toHaveBeenCalledWith({
      workspaceId: "workspace_1",
      userId: "user_1",
      deviceId: "device_current",
    });
    expect(mocks.completeKekRotation.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.acknowledgeWorkspaceWipeIfRequired.mock.invocationCallOrder[0],
    );
  });

  it("resolves each recorded KEK version when resuming a mixed-version document rewrap", async () => {
    mocks.revoke.mockResolvedValueOnce({
      revoked_device_id: "device_target",
      revocation_mode: "security",
      workspaces_needing_kek_rotation: [{ workspace_id: "workspace_1", current_kek_version: 1 }],
    });
    mocks.listDocuments.mockResolvedValueOnce({ documents: [{ id: "document_1" }] });
    mocks.getDocumentKeys.mockResolvedValueOnce({
      keys: [
        {
          encrypted_dek: "AA",
          nonce: "AA",
          key_version: 3,
          kek_version: 1,
          is_active: false,
        },
        {
          encrypted_dek: "AQ",
          nonce: "AQ",
          key_version: 4,
          kek_version: 2,
          is_active: true,
        },
      ],
    });

    await revokeDevice("device_target", "security");

    expect(mocks.resolveKekByVersion).toHaveBeenNthCalledWith(
      1,
      "workspace_1",
      1,
      expect.any(Object),
    );
    expect(mocks.resolveKekByVersion).toHaveBeenNthCalledWith(
      2,
      "workspace_1",
      2,
      expect.any(Object),
    );
    expect(mocks.resolveKekByVersion.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.unwrapDek.mock.invocationCallOrder[0],
    );
    expect(mocks.resolveKekByVersion.mock.invocationCallOrder[1]).toBeLessThan(
      mocks.unwrapDek.mock.invocationCallOrder[1],
    );
    expect(mocks.wrapDek).toHaveBeenNthCalledWith(1, {
      documentId: "document_1",
      workspaceId: "workspace_1",
      keyVersion: 3,
    });
    expect(mocks.wrapDek).toHaveBeenNthCalledWith(2, {
      documentId: "document_1",
      workspaceId: "workspace_1",
      keyVersion: 4,
    });
    expect(mocks.rewrapDocumentKeyForKekRotation).toHaveBeenNthCalledWith(
      1,
      "document_1",
      expect.objectContaining({ key_version: 3, new_kek_version: 2 }),
    );
    expect(mocks.rewrapDocumentKeyForKekRotation).toHaveBeenNthCalledWith(
      2,
      "document_1",
      expect.objectContaining({ key_version: 4, new_kek_version: 2 }),
    );
    expect(mocks.rewrapDocumentKeyForKekRotation.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.completeKekRotation.mock.invocationCallOrder[0],
    );
    expect(mocks.completeKekRotation.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.acknowledgeWorkspaceWipeIfRequired.mock.invocationCallOrder[0],
    );
  });

  it("does not delete the old KEK when a document rewrap fails", async () => {
    mocks.revoke.mockResolvedValueOnce({
      revoked_device_id: "device_target",
      revocation_mode: "security",
      workspaces_needing_kek_rotation: [{ workspace_id: "workspace_1", current_kek_version: 1 }],
    });
    mocks.listDocuments.mockResolvedValueOnce({ documents: [{ id: "document_1" }] });
    mocks.getDocumentKeys.mockResolvedValueOnce({
      keys: [
        {
          encrypted_dek: "AA",
          nonce: "AA",
          key_version: 1,
          kek_version: 1,
          is_active: true,
        },
      ],
    });
    mocks.rewrapDocumentKeyForKekRotation.mockRejectedValueOnce(new Error("rewrap_failed"));

    await expect(revokeDevice("device_target", "security")).rejects.toThrow(
      "Device removal key rotation failed",
    );
    expect(mocks.deleteKekVersion).not.toHaveBeenCalled();
    expect(mocks.completeKekRotation).not.toHaveBeenCalled();
  });

  it("reuses pending KEK material when completion is retried", async () => {
    const rotation = [{ workspace_id: "workspace_1", current_kek_version: 1 }];
    mocks.revoke.mockResolvedValue({
      revoked_device_id: "device_target",
      revocation_mode: "security",
      workspaces_needing_kek_rotation: rotation,
    });
    mocks.resolveKek.mockResolvedValue({ found: false });
    mocks.loadOfflineKekMetadata
      .mockResolvedValueOnce({ keyVersion: 1 })
      .mockResolvedValueOnce({ keyVersion: 2 });
    mocks.restoreKekFromOffline.mockResolvedValueOnce({ restored: true, keyVersion: 2 });
    mocks.completeKekRotation
      .mockRejectedValueOnce(new Error("completion_transport_failed"))
      .mockResolvedValueOnce(undefined);

    await expect(revokeDevice("device_target", "security")).rejects.toThrow(
      "Device removal key rotation failed",
    );
    await expect(revokeDevice("device_target", "security")).resolves.toEqual({ warning: null });

    expect(mocks.generateKek).toHaveBeenCalledTimes(1);
    expect(mocks.generateKek).toHaveBeenCalledWith("workspace_1", 2);
    expect(mocks.storeKekForOffline).toHaveBeenCalledTimes(1);
    expect(mocks.storeKekForOffline).toHaveBeenCalledWith({
      workspaceId: "workspace_1",
      keyVersion: 2,
    });
    expect(mocks.restoreKekFromOffline).toHaveBeenCalledTimes(1);
    expect(mocks.setActiveKekVersion).toHaveBeenCalledTimes(1);
    expect(mocks.setActiveKekVersion).toHaveBeenCalledWith("workspace_1", 2);
    expect(mocks.completeKekRotation).toHaveBeenCalledTimes(2);
  });

  it("does not regenerate missing KEK material for an active rotation", async () => {
    mocks.revoke.mockResolvedValueOnce({
      revoked_device_id: "device_target",
      revocation_mode: "security",
      workspaces_needing_kek_rotation: [{ workspace_id: "workspace_1", current_kek_version: 1 }],
    });
    mocks.startKekRotation.mockRejectedValueOnce(
      new ApiError(409, { error: "kek_rotation_already_in_progress" }),
    );
    mocks.resolveKek.mockResolvedValueOnce({ found: false });
    mocks.loadOfflineKekMetadata.mockResolvedValueOnce(null);

    await expect(revokeDevice("device_target", "security")).rejects.toThrow(
      "pending_kek_unavailable_for_active_rotation",
    );

    expect(mocks.generateKek).not.toHaveBeenCalled();
    expect(mocks.storeKekForOffline).not.toHaveBeenCalled();
    expect(mocks.persistWorkspaceKekForDevice).not.toHaveBeenCalled();
    expect(mocks.completeKekRotation).not.toHaveBeenCalled();
  });
});
