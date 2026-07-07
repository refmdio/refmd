import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { ShareMountDetail, ShareMountDocument } from "@/entities/mount";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";

const mocks = vi.hoisted(() => ({
  ensureShareWorkspaceKeyDirectoryPin: vi.fn(),
  loadMountTrustAnchor: vi.fn(),
  normalizeShareVerificationDirectory: vi.fn((directory: unknown) => directory),
  resolveShareTitle: vi.fn(),
}));

vi.mock("@/entities/mount", () => ({
  loadMountTrustAnchor: mocks.loadMountTrustAnchor,
}));

vi.mock("@/shared/lib/document/share-verification-directory", () => ({
  normalizeShareVerificationDirectory: mocks.normalizeShareVerificationDirectory,
}));

vi.mock("./title", () => ({
  resolveShareTitle: mocks.resolveShareTitle,
}));

vi.mock("./workspace-pin", () => ({
  ensureShareWorkspaceKeyDirectoryPin: mocks.ensureShareWorkspaceKeyDirectoryPin,
}));

import { resolveMountedShareOpen } from "./mount";

describe("resolveMountedShareOpen", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.loadMountTrustAnchor.mockResolvedValue({
      shareSessionKey: "mounted-share-session",
      workspacePinBootstrapHash: "workspace-pin-bootstrap-hash",
    });
    mocks.resolveShareTitle.mockResolvedValue("Mounted document");
  });

  it("passes mounted bootstrap workspace lineage into pin verification and access", async () => {
    const workspaceKeyDirectoryCheckpoint = checkpoint(1);
    const workspaceKeyDirectoryLatestCheckpoint = checkpoint(3);
    const workspaceKeyDirectoryCheckpointAncestry = [checkpoint(1), checkpoint(2)];
    const workspaceKeyDirectoryEventAncestry = [event(2), event(3)];
    const workspacePinReady = Promise.resolve();
    mocks.ensureShareWorkspaceKeyDirectoryPin.mockReturnValue(workspacePinReady);

    const result = await resolveMountedShareOpen(
      "mount-1",
      {
        mount: {
          share: {
            permission: "edit",
          },
        },
      } as ShareMountDetail,
      {
        authorization_share_id: "authorization-share-1",
        document_token: "document-token",
        encrypted_dek: "encrypted-dek",
        encrypted_key_refs: [],
        encrypted_title: null,
        encrypted_title_key_version: null,
        encrypted_title_nonce: null,
        key_version: 1,
        nonce: null,
        password_protected: false,
        permission: "edit",
        share_id: "share-1",
        verification_directory: { workspace_devices: [], share_participant_devices: [] },
        workspace_id: "workspace-1",
        workspace_pin_bootstrap: null,
        workspace_key_directory_checkpoint: workspaceKeyDirectoryCheckpoint,
        workspace_key_directory_latest_checkpoint: workspaceKeyDirectoryLatestCheckpoint,
        workspace_key_directory_checkpoint_ancestry: workspaceKeyDirectoryCheckpointAncestry,
        workspace_key_directory_event_ancestry: workspaceKeyDirectoryEventAncestry,
      } as unknown as ShareMountDocument,
      {
        principalId: "principal-1",
        displayName: "Participant",
        deviceId: "device-1",
        signingKeyId: "signing-key-1",
        encryptionPublicKey: new Uint8Array([1, 2, 3]),
      },
    );

    expect(mocks.ensureShareWorkspaceKeyDirectoryPin).toHaveBeenCalledWith({
      workspaceId: "workspace-1",
      workspacePinBootstrapHash: "workspace-pin-bootstrap-hash",
      workspacePinBootstrap: null,
      workspaceKeyDirectoryCheckpoint,
      workspaceKeyDirectoryLatestCheckpoint,
      workspaceKeyDirectoryCheckpointAncestry,
      workspaceKeyDirectoryEventAncestry,
      mismatchCode: "mount_workspace_pin_bootstrap_hash_mismatch",
    });
    expect(result.access).toMatchObject({
      source: "mounted",
      workspaceKeyDirectoryCheckpoint,
      workspaceKeyDirectoryLatestCheckpoint,
      workspaceKeyDirectoryCheckpointAncestry,
      workspaceKeyDirectoryEventAncestry,
      workspacePinReady,
    });
  });
});

function checkpoint(sequence: number): KeyDirectoryEnvelope {
  return {
    payload: {
      sequence,
      covered_event_head: {
        head_sequence: sequence,
        head_hash: `event-${sequence}`,
      },
    },
    signatures: [],
  } as unknown as KeyDirectoryEnvelope;
}

function event(sequence: number): KeyDirectoryEnvelope {
  return {
    payload: {
      sequence,
    },
    signatures: [],
  } as unknown as KeyDirectoryEnvelope;
}
