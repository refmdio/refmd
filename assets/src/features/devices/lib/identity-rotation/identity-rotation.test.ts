import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  accountType: "registered" as "registered" | "guest",
  activate: vi.fn(),
  activateServer: vi.fn(),
  beginFinalization: vi.fn(),
  buildRetirement: vi.fn(),
  buildRotation: vi.fn(),
  ensureWorkspaceIdentityKey: vi.fn(),
  finalize: vi.fn(),
  fetchDirectory: vi.fn(),
  getStatus: vi.fn(),
  importSuccessor: vi.fn(),
  restoreActivatedSuccessor: vi.fn(),
  generateSuccessor: vi.fn(),
  prepare: vi.fn(),
  wrapSuccessor: vi.fn(),
  listDevices: vi.fn(),
  persistMember: vi.fn(),
  resolveActiveKek: vi.fn(),
  setRotationDeadline: vi.fn(),
  signDeletionProof: vi.fn(),
  trustRotationCheckpoint: vi.fn(),
  setAuthState: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: () => ({
    user: { id: "user-1", accountType: mocks.accountType },
    sessionId: "session-1",
    expiresAt: null,
    identityEcdhPublic: new Uint8Array(32),
    identityHybridSigningPublicKeyMaterial: null,
  }),
  cryptoWorkerReady: () => true,
  deviceState: () => ({ deviceId: "device-1", deviceSigningKeyId: "device-signing-1" }),
  getKekResolverSession: () => ({ auth: {}, device: {} }),
  setAuthState: mocks.setAuthState,
}));
vi.mock("@/shared/api", () => ({
  devicesApi: {
    list: mocks.listDevices,
  },
  encryptionApi: {
    activateIdentityRotation: mocks.activateServer,
    finalizeIdentityRotation: mocks.finalize,
    getIdentityRotationStatus: mocks.getStatus,
    prepareIdentityRotation: mocks.prepare,
  },
}));
vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    activateIdentitySuccessor: mocks.activate,
    beginIdentitySuccessorFinalization: mocks.beginFinalization,
    generateIdentitySuccessor: mocks.generateSuccessor,
    importIdentitySuccessor: mocks.importSuccessor,
    restoreActivatedIdentitySuccessor: mocks.restoreActivatedSuccessor,
    setIdentityRotationDeadline: mocks.setRotationDeadline,
    signDeviceKeyDeletionProof: mocks.signDeletionProof,
    trustIdentityRotationCheckpoint: mocks.trustRotationCheckpoint,
    wrapIdentitySuccessorForServer: mocks.wrapSuccessor,
  }),
}));
vi.mock("@/shared/lib/crypto/kek-resolver", () => ({
  resolveActiveKek: mocks.resolveActiveKek,
}));
vi.mock("@/shared/lib/crypto/workspace-identity-directory", () => ({
  ensureWorkspaceIdentityKey: mocks.ensureWorkspaceIdentityKey,
}));
vi.mock("@/shared/lib/crypto/workspace-kek-persistence", () => ({
  persistWorkspaceKekForMember: mocks.persistMember,
}));
vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchDirectory,
}));
vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  lookupVerifiedKeyDirectoryCheckpointBodies: () => [
    {
      payload: {
        sequence: 2,
        previous_checkpoint_hash: "old-user-checkpoint-hash",
        covered_event_head: { head_sequence: 2 },
      },
      signatures: [],
    },
  ],
  lookupVerifiedKeyDirectoryEventBodies: () => [
    {
      payload: {
        event_type: "rotation_started",
        body: { new_identity_signing_key_id: "pending-signing" },
      },
      signatures: [],
    },
  ],
}));
vi.mock("@/shared/lib/crypto/key-directory/identity-rotation-events", () => ({
  buildIdentityRotationKeyDirectoryAppend: mocks.buildRotation,
  buildIdentityRetirementKeyDirectoryAppend: mocks.buildRetirement,
  identityDeletionManifest: vi.fn(() => ({ protocol: "deletion-manifest" })),
  identityDeletionManifestHash: vi.fn(() => "deletion-manifest-hash"),
  identityRevokedOldIdentityPublicKeyEventHash: vi.fn(() => "revoked-event-hash"),
  identityRotationCompletedEventHash: vi.fn(() => "rotation-completed-event-hash"),
}));

import { rotateCurrentUserIdentity } from "./identity-rotation";

const pendingStatus = {
  current_key_version: 1,
  current_encryption_key_id: "old-encryption",
  current_signing_key_id: "old-signing",
  needs_rotation: true,
  rotation_due_at: "2026-01-01T00:00:00Z",
  pending_key_version: 2,
  pending_encryption_key_id: "pending-encryption",
  pending_signing_key_id: "pending-signing",
  finalization_started: false,
  pending_encrypted_identity_hybrid_encryption_private_key_material: "AQ",
  pending_identity_hybrid_encryption_private_key_material_nonce: "Ag",
  pending_encrypted_identity_hybrid_signing_private_key_material: "Aw",
  pending_identity_hybrid_signing_private_key_material_nonce: "BA",
  required_workspace_count: 2,
  required_workspace_targets: [
    { workspace_id: "workspace-1", key_version: 3 },
    { workspace_id: "workspace-2", key_version: 3 },
  ],
  covered_workspace_count: 0,
  envelopes_complete: false,
  workspace_rewraps: [],
};

const persistedWorkspaceRewraps = [
  {
    workspace_id: "workspace-1",
    workspace_checkpoint_hash: "persisted-checkpoint-1",
    member_envelope_manifest_hash: "persisted-manifest-1",
    affected_member_envelope_ids_hash: "persisted-ids-1",
    new_identity_recipient_key_id: "pending-encryption",
  },
  {
    workspace_id: "workspace-2",
    workspace_checkpoint_hash: "persisted-checkpoint-2",
    member_envelope_manifest_hash: "persisted-manifest-2",
    affected_member_envelope_ids_hash: "persisted-ids-2",
    new_identity_recipient_key_id: "pending-encryption",
  },
];

describe("identity rotation coordinator", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.accountType = "registered";
    mocks.resolveActiveKek.mockResolvedValue({ kekVersion: 3 });
    mocks.fetchDirectory.mockResolvedValue({
      checkpoint: {
        payload: {
          sequence: 2,
          previous_checkpoint_hash: "old-user-checkpoint-hash",
          covered_event_head: { head_sequence: 2 },
        },
        signatures: [
          { signer: { signing_key_id: "old-signing" }, signature: {} },
          { signer: { signing_key_id: "pending-signing" }, signature: {} },
        ],
      },
    });
    mocks.buildRetirement.mockResolvedValue({
      events: [{ payload: {}, signatures: [] }],
      checkpoint: { payload: {}, signatures: [] },
    });
    mocks.buildRotation.mockResolvedValue({
      events: [{ payload: {}, signatures: [] }],
      checkpoint: { payload: {}, signatures: [] },
    });
    mocks.ensureWorkspaceIdentityKey.mockResolvedValue({
      checkpoint: { payload: {}, signatures: [] },
    });
    mocks.persistMember.mockImplementation(async ({ workspaceId }: { workspaceId: string }) => ({
      workspace_id: workspaceId,
      workspace_checkpoint_hash: `${workspaceId}-checkpoint`,
      member_envelope_manifest_hash: `${workspaceId}-manifest`,
      affected_member_envelope_ids_hash: `${workspaceId}-envelopes`,
      new_identity_recipient_key_id: "pending-encryption",
    }));
    mocks.listDevices.mockResolvedValue({ devices: [{ id: "device-1" }] });
    mocks.signDeletionProof.mockResolvedValue({ payload: {}, signatures: [] });
    mocks.importSuccessor.mockResolvedValue({
      ecdhPublic: new Uint8Array(32).fill(5),
      encryptionKeyId: "pending-encryption",
      hybridEncryptionPublicKeyMaterial: { owner_kind: "identity" },
      hybridSigningPublicKeyMaterial: { owner_kind: "identity" },
    });
    mocks.restoreActivatedSuccessor.mockResolvedValue({
      ecdhPublic: new Uint8Array(32).fill(5),
      encryptionKeyId: "pending-encryption",
      hybridEncryptionPublicKeyMaterial: { owner_kind: "identity" },
      hybridSigningPublicKeyMaterial: { owner_kind: "identity" },
    });
    mocks.generateSuccessor.mockResolvedValue({
      encryptionKeyId: "competing-encryption",
      signingKeyId: "competing-signing",
      hybridEncryptionPublicKeyMaterial: { owner_kind: "identity" },
      hybridSigningPublicKeyMaterial: { owner_kind: "identity" },
    });
    mocks.wrapSuccessor.mockResolvedValue({
      encryptedHybridEncryptionPrivateKeyMaterial: new Uint8Array([1]),
      hybridEncryptionPrivateKeyMaterialNonce: new Uint8Array([2]),
      encryptedHybridSigningPrivateKeyMaterial: new Uint8Array([3]),
      hybridSigningPrivateKeyMaterialNonce: new Uint8Array([4]),
    });
    mocks.beginFinalization.mockResolvedValue({
      previousEncryptionKeyId: "old-encryption",
      previousSigningKeyId: "old-signing",
      successorEncryptionKeyId: "pending-encryption",
      successorSigningKeyId: "pending-signing",
      oldPrivateKeyUseBlocked: true,
    });
    mocks.activate.mockResolvedValue({ oldPrivateKeyDeleted: true });
    mocks.activateServer.mockImplementation(async () => ({
      ...pendingStatus,
      finalization_started: true,
    }));
    mocks.finalize.mockResolvedValue({
      ...pendingStatus,
      current_key_version: 2,
      current_encryption_key_id: "pending-encryption",
      current_signing_key_id: "pending-signing",
      pending_key_version: null,
    });
  });

  it("does not delete the old identity when any workspace rewrap fails", async () => {
    mocks.getStatus.mockResolvedValue(pendingStatus);
    mocks.ensureWorkspaceIdentityKey
      .mockResolvedValueOnce({ checkpoint: { payload: {}, signatures: [] } })
      .mockRejectedValueOnce(new Error("workspace_rewrap_failed"));

    await expect(rotateCurrentUserIdentity()).rejects.toThrow("workspace_rewrap_failed");

    expect(mocks.persistMember).toHaveBeenCalledTimes(1);
    expect(mocks.activate).not.toHaveBeenCalled();
    expect(mocks.beginFinalization).not.toHaveBeenCalled();
    expect(mocks.finalize).not.toHaveBeenCalled();
  });

  it("continues the canonical pending rotation when another device wins prepare", async () => {
    const { ApiError } = await import("@/shared/api/core");
    const initialStatus = {
      ...pendingStatus,
      pending_key_version: null,
      pending_encryption_key_id: null,
      pending_signing_key_id: null,
      pending_encrypted_identity_hybrid_encryption_private_key_material: null,
      pending_identity_hybrid_encryption_private_key_material_nonce: null,
      pending_encrypted_identity_hybrid_signing_private_key_material: null,
      pending_identity_hybrid_signing_private_key_material_nonce: null,
    };
    const completeStatus = {
      ...pendingStatus,
      covered_workspace_count: 2,
      envelopes_complete: true,
      workspace_rewraps: persistedWorkspaceRewraps,
    };
    mocks.getStatus
      .mockResolvedValueOnce(initialStatus)
      .mockResolvedValueOnce(pendingStatus)
      .mockResolvedValueOnce(completeStatus);
    mocks.prepare.mockRejectedValue(
      new ApiError(409, { error: "identity_rotation_already_pending" }),
    );

    await rotateCurrentUserIdentity();

    expect(mocks.prepare).toHaveBeenCalledTimes(1);
    expect(mocks.importSuccessor).toHaveBeenCalledWith(
      expect.objectContaining({
        encryptionKeyId: "pending-encryption",
        signingKeyId: "pending-signing",
      }),
    );
    expect(mocks.persistMember).toHaveBeenCalledTimes(2);
    expect(mocks.finalize).toHaveBeenCalledTimes(1);
  });

  it("blocks old-key use, deletes it, then finalizes after every envelope is covered", async () => {
    mocks.getStatus.mockResolvedValueOnce(pendingStatus).mockResolvedValueOnce({
      ...pendingStatus,
      covered_workspace_count: 2,
      envelopes_complete: true,
      workspace_rewraps: persistedWorkspaceRewraps,
    });

    await rotateCurrentUserIdentity();

    expect(mocks.persistMember).toHaveBeenCalledTimes(2);
    expect(mocks.beginFinalization).toHaveBeenCalledTimes(1);
    expect(mocks.activateServer).toHaveBeenCalledTimes(1);
    expect(mocks.activate).toHaveBeenCalledTimes(1);
    expect(mocks.finalize).toHaveBeenCalledWith(
      expect.objectContaining({
        key_version: 2,
        deletion_proof: expect.objectContaining({
          completion_manifest: expect.objectContaining({
            workspace_rewraps: persistedWorkspaceRewraps,
          }),
          old_private_key_use_blocked: true,
          persistent_identity_deletion_authorized: true,
        }),
      }),
      { rrpDeviceId: "device-1" },
    );
    expect(mocks.activateServer.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.activate.mock.invocationCallOrder[0],
    );
    expect(mocks.activate.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.finalize.mock.invocationCallOrder[0],
    );
    expect(mocks.fetchDirectory).toHaveBeenCalledTimes(2);
    expect(mocks.activate.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.trustRotationCheckpoint.mock.invocationCallOrder[0],
    );
  });

  it("keeps the old key deleted while a later finalize retry succeeds", async () => {
    const completeStatus = {
      ...pendingStatus,
      covered_workspace_count: 2,
      envelopes_complete: true,
      workspace_rewraps: persistedWorkspaceRewraps,
    };
    mocks.getStatus.mockResolvedValue(completeStatus);
    mocks.finalize
      .mockRejectedValueOnce(new Error("finalize_unavailable"))
      .mockRejectedValueOnce(new Error("finalize_unavailable"))
      .mockRejectedValueOnce(new Error("finalize_unavailable"))
      .mockResolvedValue({
        ...completeStatus,
        current_key_version: 2,
        current_encryption_key_id: "pending-encryption",
        current_signing_key_id: "pending-signing",
        pending_key_version: null,
      });
    const timeout = vi.spyOn(globalThis, "setTimeout").mockImplementation((callback) => {
      if (typeof callback === "function") callback();
      return 0 as unknown as ReturnType<typeof setTimeout>;
    });

    await expect(rotateCurrentUserIdentity()).rejects.toThrow("finalize_unavailable");
    expect(mocks.activate).toHaveBeenCalledTimes(1);
    await rotateCurrentUserIdentity();

    expect(mocks.beginFinalization).toHaveBeenCalledTimes(2);
    expect(mocks.activate).toHaveBeenCalledTimes(2);
    expect(mocks.finalize).toHaveBeenCalledTimes(4);
    expect(mocks.finalize).toHaveBeenLastCalledWith(
      expect.objectContaining({
        deletion_proof: expect.objectContaining({
          old_encryption_key_id: "old-encryption",
          old_signing_key_id: "old-signing",
        }),
      }),
      { rrpDeviceId: "device-1" },
    );
    timeout.mockRestore();
  });

  it("reconstructs finalization after a fresh-worker reload without importing the predecessor", async () => {
    const completeStatus = {
      ...pendingStatus,
      finalization_started: true,
      covered_workspace_count: 2,
      envelopes_complete: true,
      workspace_rewraps: persistedWorkspaceRewraps,
    };
    mocks.getStatus.mockResolvedValue(completeStatus);

    await rotateCurrentUserIdentity();

    expect(mocks.restoreActivatedSuccessor).toHaveBeenCalledWith(
      expect.objectContaining({
        encryptionKeyId: "pending-encryption",
        previousEncryptionKeyId: "old-encryption",
        previousSigningKeyId: "old-signing",
      }),
    );
    expect(mocks.importSuccessor).not.toHaveBeenCalled();
    expect(mocks.finalize).toHaveBeenCalledTimes(1);
  });

  it("rewraps every required workspace for an overdue persisted guest identity rotation", async () => {
    mocks.accountType = "guest";
    const completeStatus = {
      ...pendingStatus,
      rotation_due_at: "2020-01-01T00:00:00Z",
      covered_workspace_count: 2,
      envelopes_complete: true,
      workspace_rewraps: persistedWorkspaceRewraps,
    };
    mocks.getStatus
      .mockResolvedValueOnce({ ...pendingStatus, rotation_due_at: "2020-01-01T00:00:00Z" })
      .mockResolvedValueOnce(completeStatus);

    await expect(rotateCurrentUserIdentity()).resolves.toEqual(
      expect.objectContaining({ current_key_version: 2 }),
    );

    expect(mocks.activateServer).toHaveBeenCalledTimes(1);
    expect(mocks.finalize).toHaveBeenCalledTimes(1);
    expect(mocks.resolveActiveKek).toHaveBeenCalledTimes(2);
    expect(mocks.persistMember).toHaveBeenCalledTimes(2);
  });

  it("accepts status confirmation when a finalize response is lost after deletion", async () => {
    const completeStatus = {
      ...pendingStatus,
      covered_workspace_count: 2,
      envelopes_complete: true,
      workspace_rewraps: persistedWorkspaceRewraps,
    };
    const committedStatus = {
      ...completeStatus,
      current_key_version: 2,
      current_encryption_key_id: "pending-encryption",
      current_signing_key_id: "pending-signing",
      pending_key_version: null,
    };
    mocks.getStatus
      .mockResolvedValueOnce(completeStatus)
      .mockResolvedValueOnce(completeStatus)
      .mockResolvedValueOnce(committedStatus);
    mocks.finalize.mockRejectedValueOnce(new Error("response_lost"));

    await expect(rotateCurrentUserIdentity()).resolves.toEqual(committedStatus);

    expect(mocks.finalize).toHaveBeenCalledTimes(1);
    expect(mocks.activate).toHaveBeenCalledTimes(1);
    expect(mocks.activate.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.finalize.mock.invocationCallOrder[0],
    );
  });
});
