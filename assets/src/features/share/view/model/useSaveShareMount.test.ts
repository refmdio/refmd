import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  currentWorkspaceId: vi.fn(),
  allWorkspaces: vi.fn(),
  createShareMount: vi.fn(),
  invalidateQueries: vi.fn(),
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

import { useSaveShareMount } from "./useSaveShareMount";

describe("useSaveShareMount", () => {
  let dispose: (() => void) | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "user-1" } });
    mocks.currentWorkspaceId.mockReturnValue("workspace-1");
    mocks.allWorkspaces.mockReturnValue([{ id: "workspace-fallback" }]);
  });

  afterEach(() => {
    dispose?.();
    dispose = undefined;
  });

  it("creates a mount, invalidates workspace mounts, and calls onSaved", async () => {
    const onSaved = vi.fn();
    mocks.createShareMount.mockResolvedValue({ id: "mount-1" });

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
      parent_id: null,
    });
    expect(mocks.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["share-mounts", "workspace-1"],
    });
    expect(onSaved).toHaveBeenCalledTimes(1);
    expect(state.isSaved()).toBe(true);
  });

  it("uses the first workspace when no current workspace is selected", async () => {
    mocks.currentWorkspaceId.mockReturnValue(null);
    mocks.createShareMount.mockResolvedValue({ id: "mount-2" });

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

  it("treats conflict responses with an existing mount id as saved", async () => {
    const onSaved = vi.fn();
    mocks.createShareMount.mockRejectedValue({ data: { mount: { id: "existing-mount" } } });

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
    expect(mocks.invalidateQueries).not.toHaveBeenCalled();
  });
});
