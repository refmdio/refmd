import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { DocumentResponse } from "@/entities/document";

const mocks = vi.hoisted(() => ({
  cryptoWorkerReady: vi.fn(),
  invalidateQueries: vi.fn(),
  createManagedShare: vi.fn(),
  buildShareExclusionKeyDirectoryAppend: vi.fn(),
  buildShareKeyScopeKeyDirectoryAppend: vi.fn(),
  buildShareRevokedKeyDirectoryAppend: vi.fn(),
  buildShareSettingsKeyDirectoryAppend: vi.fn(),
  listDocumentShares: vi.fn(),
  updateDocumentShare: vi.fn(),
  rememberShareAccess: vi.fn(),
  readShareUrl: vi.fn(),
  restoreShareAccesses: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  cryptoWorkerReady: mocks.cryptoWorkerReady,
}));

vi.mock("@tanstack/solid-query", () => ({
  createQuery: () => ({ data: { shares: [] } }),
  useQueryClient: () => ({
    invalidateQueries: mocks.invalidateQueries,
  }),
}));

vi.mock("@/shared/api", () => ({
  sharesApi: {
    listDocumentShares: mocks.listDocumentShares,
    updateDocumentShare: mocks.updateDocumentShare,
  },
}));

vi.mock("../../lib/manage/build-share", () => ({
  buildShareExclusionKeyDirectoryAppend: mocks.buildShareExclusionKeyDirectoryAppend,
  buildShareKeyScopeKeyDirectoryAppend: mocks.buildShareKeyScopeKeyDirectoryAppend,
  buildShareRevokedKeyDirectoryAppend: mocks.buildShareRevokedKeyDirectoryAppend,
  buildShareSettingsKeyDirectoryAppend: mocks.buildShareSettingsKeyDirectoryAppend,
  createManagedShare: mocks.createManagedShare,
  shareExpiresEventSequence: (sequence: number | null) => sequence ?? Number.MAX_SAFE_INTEGER,
}));

vi.mock("../../lib/manage/manage-tokens", () => ({
  forgetShareAccess: vi.fn(),
  readShareUrl: mocks.readShareUrl,
  rememberShareAccess: mocks.rememberShareAccess,
  restoreShareAccesses: mocks.restoreShareAccesses,
}));

vi.mock("./folder-share-key-update", () => ({
  activeDescendantOptions: () => [],
  expandedExclusionIds: () => new Set<string>(),
  prepareFolderShareKeyUpdate: vi.fn(),
}));

import { useShareManagement } from "./use-share-management";

const document = {
  id: "doc-1",
  workspace_id: "workspace-1",
  doc_type: "document",
} as DocumentResponse;

describe("useShareManagement", () => {
  let dispose: (() => void) | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.cryptoWorkerReady.mockReturnValue(false);
    mocks.createManagedShare.mockResolvedValue({
      id: "share-1",
      share_slug: "share-slug",
      share_url_fragment: "cap=secret",
      workspace_pin_bootstrap_hash: "workspace-pin-hash",
    });
    mocks.buildShareSettingsKeyDirectoryAppend.mockResolvedValue({
      workspace_key_directory_events: [],
      workspace_key_directory_checkpoint: { payload: {} },
    });
  });

  afterEach(() => {
    dispose?.();
    dispose = undefined;
  });

  function createModel() {
    return createRoot((rootDispose) => {
      dispose = rootDispose;
      return useShareManagement({
        document: () => document,
        documents: () => [document],
        canDeleteShares: () => true,
        getTitle: () => "Shared doc",
        setError: vi.fn(),
      });
    });
  }

  it("passes the selected create expiry to the signed share creation payload", async () => {
    const state = createModel();
    state.setExpiryDays(14);

    await state.createShare();

    expect(mocks.createManagedShare).toHaveBeenCalledWith(
      expect.objectContaining({
        expiresEventSequence: 14,
      }),
    );
  });

  it("passes the selected update expiry to the signed settings payload and API body", async () => {
    const state = createModel();

    await state.updateShareSettings("share-1", {
      currentExpiresEventSequence: 100,
      currentMaxViews: Number.MAX_SAFE_INTEGER,
      expiryDays: 30,
      accessLimitInput: "25",
    });

    expect(mocks.buildShareSettingsKeyDirectoryAppend).toHaveBeenCalledWith({
      workspaceId: "workspace-1",
      shareId: "share-1",
      expiresEventSequence: 30,
      maxViews: 25,
    });
    expect(mocks.updateDocumentShare).toHaveBeenCalledWith(
      "doc-1",
      "share-1",
      expect.objectContaining({
        expires_event_sequence: 30,
        max_views: 25,
      }),
    );
  });

  it("maps explicit no-expiry updates to the unbounded expiry sentinel", async () => {
    const state = createModel();

    await state.updateShareSettings("share-1", {
      currentExpiresEventSequence: 100,
      currentMaxViews: 5,
      expiryDays: null,
    });

    expect(mocks.buildShareSettingsKeyDirectoryAppend).toHaveBeenCalledWith(
      expect.objectContaining({
        expiresEventSequence: Number.MAX_SAFE_INTEGER,
        maxViews: 5,
      }),
    );
  });
});
