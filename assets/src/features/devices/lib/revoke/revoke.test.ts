import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  buildKekOldKeyDeletionManifestHash: vi.fn(),
  buildKekRotationCompletionKeyDirectoryAppend: vi.fn(),
  getWorkspaceIds: vi.fn(),
  getWorkspaceMemberKeys: vi.fn(),
  prepareKekRotationCompletion: vi.fn(),
  completeKekRotation: vi.fn(),
  startKekRotation: vi.fn(),
  generateKek: vi.fn(),
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
  },
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
}));

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
    mocks.tofuVerify.mockResolvedValue({ status: "known_trusted" });
    mocks.tofuUpdateLastSeen.mockResolvedValue(undefined);
    mocks.verifyDeviceApprovalSignature.mockResolvedValue(true);
    mocks.verifyGenesisDeviceBootstrapSignature.mockResolvedValue(true);
    mocks.verifyRecoveryDeviceApprovalSignature.mockResolvedValue(true);
    mocks.generateKek.mockResolvedValue(undefined);
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
    mocks.signDeviceKeyDeletionProof.mockResolvedValue({ proof: "device-key-deletion" });
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
      device_key_deletion_proofs: [{ proof: "device-key-deletion" }],
      wipe_required_device_ids: [],
    });
  });
});
