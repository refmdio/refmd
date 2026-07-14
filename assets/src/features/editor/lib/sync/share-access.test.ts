import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import { ensureSharedDekCached, refreshSharedDocumentAccess } from "./share-access";

const mocks = vi.hoisted(() => ({
  advanceKeyDirectoryPinWithProof: vi.fn(),
  fetchShareDocumentBootstrap: vi.fn(),
  getKeyDirectoryPin: vi.fn(),
  hasDek: vi.fn(),
  prewarmSharedDekForAccess: vi.fn(),
  setDocumentReadOnly: vi.fn(),
}));

vi.mock("./crypto-worker", () => ({
  getDocumentCryptoWorker: vi.fn(() => ({
    fetchShareDocumentBootstrap: mocks.fetchShareDocumentBootstrap,
    hasDek: mocks.hasDek,
  })),
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin: mocks.getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope: vi.fn(
    (envelope: KeyDirectoryEnvelope) => `checkpoint-${envelope.payload.sequence}`,
  ),
}));

vi.mock("../../model/document-state/signals", () => ({
  setDocumentReadOnly: mocks.setDocumentReadOnly,
}));

vi.mock("@/shared/lib/crypto/share-dek-prewarm", () => ({
  getSharedDekCacheKey: vi.fn(
    (documentId: string, shareId: string) => `share:${shareId}:${documentId}`,
  ),
  prewarmSharedDekForAccess: mocks.prewarmSharedDekForAccess,
}));

describe("ensureSharedDekCached", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.hasDek.mockResolvedValue(false);
    mocks.prewarmSharedDekForAccess.mockResolvedValue(undefined);
    mocks.advanceKeyDirectoryPinWithProof.mockResolvedValue(undefined);
    mocks.getKeyDirectoryPin.mockResolvedValue(keyDirectoryPin(2));
  });

  it("prewarms the requested version when state version matches but the worker cache is empty", async () => {
    const staleReady = Promise.resolve();
    const access = {
      kind: "share",
      source: "link",
      shareId: "share-1",
      shareSlug: "share-slug",
      workspaceId: "workspace-1",
      keyVersion: 2,
      encryptedKeyRefs: ["ref-v2"],
      shareDekReady: staleReady,
    };
    const state = {
      access,
      dekResolved: true,
      keyVersion: 2,
    };

    await ensureSharedDekCached(state as never, "document-1", 2);

    expect(mocks.hasDek).toHaveBeenCalledWith("document-1", 2, "share:share-1:document-1");
    expect(mocks.prewarmSharedDekForAccess).toHaveBeenCalledWith(access, "document-1", 2);
  });
});

describe("refreshSharedDocumentAccess", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.advanceKeyDirectoryPinWithProof.mockResolvedValue(undefined);
    mocks.getKeyDirectoryPin.mockResolvedValue(keyDirectoryPin(2));
  });

  it.each([
    "workspace_key_directory_checkpoint",
    "workspace_key_directory_latest_checkpoint",
    "workspace_key_directory_checkpoint_ancestry",
    "workspace_key_directory_event_ancestry",
  ])("fails closed when refresh omits %s", async (field) => {
    const response = shareBootstrapResponse(2);
    delete response[field];
    mocks.fetchShareDocumentBootstrap.mockResolvedValue(response);

    await expect(refreshSharedDocumentAccess(shareState() as never)).rejects.toThrow(
      /share_workspace_key_directory_.*_invalid/,
    );
    expect(mocks.advanceKeyDirectoryPinWithProof).not.toHaveBeenCalled();
  });

  it.each(["key_directory_checkpoint_rollback", "key_directory_checkpoint_fork"])(
    "fails closed when canonical pin advancement rejects %s",
    async (reason) => {
      mocks.fetchShareDocumentBootstrap.mockResolvedValue(shareBootstrapResponse(1));
      mocks.advanceKeyDirectoryPinWithProof.mockRejectedValue(new Error(reason));

      const access = await refreshSharedDocumentAccess(shareState() as never);

      await expect(access.workspacePinReady).rejects.toThrow(
        "share_workspace_pin_bootstrap_hash_mismatch",
      );
      expect(mocks.advanceKeyDirectoryPinWithProof).toHaveBeenCalledWith(
        expect.objectContaining({
          scopeKind: "workspace",
          scopeId: "workspace-1",
          checkpointEnvelope: checkpoint(1),
        }),
      );
    },
  );
});

function shareState() {
  return {
    stateKey: "state-1",
    workspaceId: "workspace-1",
    access: {
      kind: "share",
      source: "link",
      documentToken: "document-token",
      shareId: "share-1",
      authorizationShareId: "share-1",
      shareSlug: "share-slug",
      participantPrincipalId: "participant-1",
      participantDisplayName: "Guest",
      participantDeviceId: "participant-device-1",
      participantSigningKeyId: "participant-signing-key-1",
      participantEncryptionPublicKey: "participant-encryption-key-1",
      permission: "edit",
      passwordProtected: false,
      workspaceId: "workspace-1",
      workspacePinBootstrapHash: "bootstrap-hash",
      keyVersion: 1,
      encryptedKeyRefs: ["ref-v1"],
      workspaceKeyDirectoryCheckpoint: checkpoint(2),
      workspaceKeyDirectoryLatestCheckpoint: checkpoint(2),
      workspaceKeyDirectoryCheckpointAncestry: [],
      workspaceKeyDirectoryEventAncestry: [],
      verificationDirectory: { workspace_devices: [], share_participant_devices: [] },
      shareTrustAnchor: {
        shareId: "share-1",
        scopeKind: "document",
        scopeId: "document-1",
        permission: "edit",
        passwordProtected: false,
        workspacePinBootstrapHash: "bootstrap-hash",
        shareTokenHash: "share-token-hash",
        createdEventHash: "created-event-hash",
        latestBootstrapEventHash: "bootstrap-event-hash",
        capabilityContextHash: "capability-context-hash",
        shareCapabilitySecretCommitment: "share-secret-commitment",
        passwordCapabilitySecretCommitment: "password-secret-commitment",
      },
    },
  };
}

function shareBootstrapResponse(sequence: number): Record<string, unknown> {
  return {
    document_id: "document-1",
    share_id: "share-1",
    authorization_share_id: "share-1",
    scope_kind: "document",
    scope_id: "document-1",
    permission: "edit",
    password_protected: false,
    workspace_id: "workspace-1",
    key_version: 1,
    encrypted_key_refs: ["ref-v1"],
    workspace_key_directory_checkpoint: checkpoint(2),
    workspace_key_directory_latest_checkpoint: checkpoint(sequence),
    workspace_key_directory_checkpoint_ancestry: [],
    workspace_key_directory_event_ancestry: [],
    verification_directory: { workspace_devices: [], share_participant_devices: [] },
    share_token_hash: "share-token-hash",
    created_event_hash: "created-event-hash",
    latest_bootstrap_event_hash: "bootstrap-event-hash",
    capability_context_hash: "capability-context-hash",
    share_capability_secret_commitment: "share-secret-commitment",
    password_capability_secret_commitment: "password-secret-commitment",
  };
}

function checkpoint(sequence: number): KeyDirectoryEnvelope {
  return {
    payload: {
      sequence,
      covered_event_head: { head_sequence: sequence, head_hash: `event-${sequence}` },
    },
    signatures: [],
  } as unknown as KeyDirectoryEnvelope;
}

function keyDirectoryPin(sequence: number) {
  return {
    pinKey: "workspace:workspace-1",
    scopeKind: "workspace",
    scopeId: "workspace-1",
    checkpointSequence: sequence,
    checkpointHash: `checkpoint-${sequence}`,
    eventHeadSequence: sequence,
    eventHeadHash: `event-${sequence}`,
    suitePolicyVersion: 1,
    minSuiteRank: 1,
    allowedSuiteIdsHash: "suite-policy",
    observedAt: 1,
  };
}
