import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  currentWorkspaceId: vi.fn(),
  allWorkspaces: vi.fn(),
  createShareMount: vi.fn(),
  invalidateQueries: vi.fn(),
  readShareUrlFragmentFromLocation: vi.fn(),
  readWorkspacePinBootstrapHashFromLocation: vi.fn(),
  readShareSessionTrustAnchor: vi.fn(),
  rememberMountedShareParticipantSession: vi.fn(),
  rememberMountTrustAnchor: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
}));

vi.mock("@/entities/workspace", () => ({
  currentWorkspaceId: mocks.currentWorkspaceId,
  useWorkspaces: () => ({
    allWorkspaces: mocks.allWorkspaces,
  }),
}));

vi.mock("@/shared/api", () => ({
  sharesApi: {
    createShareMount: mocks.createShareMount,
  },
}));

vi.mock("@tanstack/solid-query", () => ({
  useQueryClient: () => ({
    invalidateQueries: mocks.invalidateQueries,
  }),
}));

vi.mock("@/entities/mount", () => ({
  mountedShareSessionKey: (mountId: string) => `mount:${mountId}`,
  readShareUrlFragmentFromLocation: mocks.readShareUrlFragmentFromLocation,
  readWorkspacePinBootstrapHashFromLocation: mocks.readWorkspacePinBootstrapHashFromLocation,
  rememberMountTrustAnchor: mocks.rememberMountTrustAnchor,
}));

vi.mock("../../lib/session/session", () => ({
  readShareSessionTrustAnchor: mocks.readShareSessionTrustAnchor,
  rememberMountedShareParticipantSession: mocks.rememberMountedShareParticipantSession,
}));

import { useSaveShareMount } from "./use-save-share-mount";

describe("useSaveShareMount", () => {
  let dispose: (() => void) | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "user-1" } });
    mocks.currentWorkspaceId.mockReturnValue("workspace-1");
    mocks.allWorkspaces.mockReturnValue([{ id: "workspace-1" }]);
    mocks.readWorkspacePinBootstrapHashFromLocation.mockReturnValue(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    mocks.readShareUrlFragmentFromLocation.mockReturnValue(
      "cap=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&wpb=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    mocks.readShareSessionTrustAnchor.mockResolvedValue({
      anchor: {
        protocol: "refmd.share-session-trust-anchor",
      },
      workspacePinBootstrapHash: null,
      shareCapabilitySecretCommitment: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      passwordCapabilitySecretCommitment: "none",
      hasShareDekEncryptionKey: true,
    });
    mocks.rememberMountedShareParticipantSession.mockResolvedValue(undefined);
  });

  afterEach(() => {
    dispose?.();
    dispose = undefined;
  });

  it("creates a mount, invalidates workspace mounts, and calls onSaved", async () => {
    const onSaved = vi.fn();
    mocks.createShareMount.mockResolvedValue({ id: "mount-1", share_id: "share-1" });

    const state = createRoot((rootDispose) => {
      dispose = rootDispose;
      return useSaveShareMount({
        shareSlug: "share-slug",
        targetKind: "folder",
        targetToken: "folder-token",
        onSaved,
      });
    });

    await state.save();

    expect(mocks.createShareMount).toHaveBeenCalledWith({
      workspace_id: "workspace-1",
      share_slug: "share-slug",
      target_kind: "folder",
      target_token: "folder-token",
      authenticated_workspace_pin_bootstrap_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });
    expect(mocks.rememberMountedShareParticipantSession).toHaveBeenCalledWith({
      sourceShareSlug: "share-slug",
      mountSessionKey: "mount:mount-1",
      shareId: "share-1",
    });
    expect(mocks.rememberMountTrustAnchor).toHaveBeenCalledWith({
      mountId: "mount-1",
      shareId: "share-1",
      shareSessionKey: "mount:mount-1",
      targetKind: "folder",
      targetToken: "folder-token",
      targetTitle: null,
      workspacePinBootstrapHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });
    expect(mocks.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["share-mounts", "workspace-1"],
    });
    expect(onSaved).toHaveBeenCalledTimes(1);
    expect(state.isSaved()).toBe(true);
  });

  it("uses the only workspace when no current workspace is selected", async () => {
    mocks.currentWorkspaceId.mockReturnValue(null);
    mocks.allWorkspaces.mockReturnValue([{ id: "workspace-fallback" }]);
    mocks.createShareMount.mockResolvedValue({ id: "mount-2", share_id: "share-2" });

    const state = createRoot((rootDispose) => {
      dispose = rootDispose;
      return useSaveShareMount({
        shareSlug: "share-slug",
        targetKind: "document",
        targetToken: "document-token",
      });
    });

    await state.save();

    expect(mocks.createShareMount).toHaveBeenCalledWith(
      expect.objectContaining({ workspace_id: "workspace-fallback" }),
    );
    expect(mocks.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["share-mounts", "workspace-fallback"],
    });
  });

  it("requires an explicit workspace when multiple workspaces are available", async () => {
    mocks.currentWorkspaceId.mockReturnValue("workspace-1");
    mocks.allWorkspaces.mockReturnValue([
      { id: "workspace-1", name: "Workspace 1" },
      { id: "workspace-2", name: "Workspace 2" },
    ]);
    mocks.createShareMount.mockResolvedValue({ id: "mount-3", share_id: "share-3" });

    const state = createRoot((rootDispose) => {
      dispose = rootDispose;
      return useSaveShareMount({
        shareSlug: "share-slug",
        targetKind: "document",
        targetToken: "document-token",
      });
    });

    expect(state.canSave()).toBe(false);
    expect(state.canChooseWorkspace()).toBe(true);

    await state.save();

    expect(mocks.createShareMount).not.toHaveBeenCalled();

    await state.save("workspace-2");

    expect(mocks.createShareMount).toHaveBeenCalledWith(
      expect.objectContaining({ workspace_id: "workspace-2" }),
    );
    expect(mocks.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["share-mounts", "workspace-2"],
    });
  });

  it("treats conflict responses with an existing mount id as saved", async () => {
    const onSaved = vi.fn();
    mocks.createShareMount.mockRejectedValue({
      data: { mount: { id: "existing-mount", share_id: "share-1" } },
    });

    const state = createRoot((rootDispose) => {
      dispose = rootDispose;
      return useSaveShareMount({
        shareSlug: "share-slug",
        targetKind: "folder",
        targetToken: "folder-token",
        onSaved,
      });
    });

    await state.save();

    expect(state.isSaved()).toBe(true);
    expect(onSaved).toHaveBeenCalledTimes(1);
    expect(mocks.rememberMountedShareParticipantSession).toHaveBeenCalledWith({
      sourceShareSlug: "share-slug",
      mountSessionKey: "mount:existing-mount",
      shareId: "share-1",
    });
    expect(mocks.rememberMountTrustAnchor).toHaveBeenCalledWith({
      mountId: "existing-mount",
      shareId: "share-1",
      shareSessionKey: "mount:existing-mount",
      targetKind: "folder",
      targetToken: "folder-token",
      targetTitle: null,
      workspacePinBootstrapHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });
    expect(mocks.invalidateQueries).not.toHaveBeenCalled();
  });
});
