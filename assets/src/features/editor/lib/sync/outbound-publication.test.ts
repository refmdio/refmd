import * as Y from "yjs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DocumentState } from "../../model/document-state/types";

const mocks = vi.hoisted(() => {
  class MockApiError extends Error {
    status: number;
    body: Record<string, unknown>;
    code: string | null;

    constructor(status: number, body: Record<string, unknown>) {
      super("api error");
      this.status = status;
      this.body = body;
      this.code = typeof body.error === "string" ? body.error : null;
    }
  }

  return {
    ApiError: MockApiError,
    getDocumentState: vi.fn(),
    getDocumentPublicationState: vi.fn(),
    setDocumentPublicationState: vi.fn(),
    getDocumentList: vi.fn(),
    getDocumentById: vi.fn(),
    onDocumentEvent: vi.fn(),
    offDocumentEvent: vi.fn(),
    syncPublicationContent: vi.fn(),
    getWorkspace: vi.fn(),
    getQueryData: vi.fn(),
    setQueryData: vi.fn(),
    invalidateQueries: vi.fn(),
    blake3Hash: vi.fn(async () => new Uint8Array([1, 2, 3])),
  };
});

vi.mock("@/shared/api", () => ({
  ApiError: mocks.ApiError,
  publicApi: {
    syncPublicationContent: mocks.syncPublicationContent,
  },
  workspacesApi: {
    get: mocks.getWorkspace,
  },
}));

vi.mock("@/shared/lib/document/manager", () => ({
  getDocumentEvents: () => ({
    on: mocks.onDocumentEvent,
    offref: mocks.offDocumentEvent,
  }),
  getDocumentRuntime: () => ({
    getDocumentList: mocks.getDocumentList,
    getDocumentById: mocks.getDocumentById,
  }),
}));

vi.mock("@/shared/lib/document/publication-state", () => ({
  getDocumentPublicationState: mocks.getDocumentPublicationState,
  setDocumentPublicationState: mocks.setDocumentPublicationState,
}));

vi.mock("@/shared/lib/query/client", () => ({
  queryClient: {
    getQueryData: mocks.getQueryData,
    setQueryData: mocks.setQueryData,
    invalidateQueries: mocks.invalidateQueries,
  },
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    blake3Hash: mocks.blake3Hash,
  }),
}));

vi.mock("../../model/document-state/store", () => ({
  getDocumentState: mocks.getDocumentState,
}));

import {
  applyInitialPublicationState,
  applyPublicationStatusChanged,
  installPublicationRenameAutoSync,
  queuePublicationAutoSync,
  queuePublicationSaveSync,
} from "./outbound-publication";

function lastSavedState(content: string): Uint8Array {
  const doc = new Y.Doc();
  doc.getText("content").insert(0, content);
  const update = Y.encodeStateAsUpdate(doc);
  doc.destroy();
  return update;
}

function workspaceEnabledQuery(
  enabled: boolean | undefined,
  initialWorkspaceList?: {
    workspaces: Array<{
      id: string;
      public_publishing_enabled?: boolean;
    }>;
  },
) {
  let workspace:
    | {
        id: string;
        public_publishing_enabled: boolean;
      }
    | undefined =
    enabled == null ? undefined : { id: "workspace-1", public_publishing_enabled: enabled };
  let workspaceList = initialWorkspaceList;

  mocks.getQueryData.mockImplementation((key: unknown[]) => {
    if (key[0] === "workspace" && key[1] === "workspace-1") {
      return workspace;
    }
    if (key[0] === "workspaces") {
      return workspaceList;
    }
    return undefined;
  });
  mocks.setQueryData.mockImplementation((key: unknown[], updater) => {
    if (key[0] === "workspace" && key[1] === "workspace-1") {
      workspace = typeof updater === "function" ? updater(workspace) : updater;
      return;
    }
    if (key[0] === "workspaces") {
      workspaceList = typeof updater === "function" ? updater(workspaceList) : updater;
    }
  });
}

describe("publication outbound sync", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getDocumentPublicationState.mockReturnValue(null);
    mocks.getDocumentState.mockReturnValue(undefined);
    mocks.getDocumentList.mockReturnValue([
      {
        id: "document-1",
        title: "Old Title",
        workspaceId: "workspace-1",
        parentId: null,
        docType: "document",
        archivedAt: null,
        canSyncPublication: true,
      },
    ]);
    mocks.getDocumentById.mockResolvedValue({
      id: "document-1",
      title: "Old Title",
      text: "Published body",
      release: vi.fn(),
    });
    mocks.syncPublicationContent.mockResolvedValue({ updated_at: "2026-05-02T00:00:00Z" });
    mocks.getWorkspace.mockResolvedValue({
      id: "workspace-1",
      public_publishing_enabled: true,
    });
    mocks.onDocumentEvent.mockReturnValue({});
    mocks.setQueryData.mockImplementation(() => undefined);
    mocks.invalidateQueries.mockResolvedValue(undefined);
    workspaceEnabledQuery(true);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("syncs a published closed document after rename when workspace publishing is enabled", async () => {
    let renameHandler:
      | ((documentId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void)
      | undefined;
    mocks.onDocumentEvent.mockImplementation((_event, handler) => {
      renameHandler = handler;
      return {};
    });

    const dispose = installPublicationRenameAutoSync();
    renameHandler?.("document-1", "Old Title", "New Title", true);

    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalledWith(
        "document-1",
        expect.objectContaining({
          title: "New Title",
          content: "Published body",
        }),
      );
    });

    dispose();
    expect(mocks.offDocumentEvent).toHaveBeenCalledTimes(1);
  });

  it("does not sync a published closed document when the user lacks document write permission", async () => {
    mocks.getDocumentList.mockReturnValue([
      {
        id: "document-1",
        title: "Old Title",
        workspaceId: "workspace-1",
        parentId: null,
        docType: "document",
        archivedAt: null,
        canSyncPublication: false,
      },
    ]);
    let renameHandler:
      | ((documentId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void)
      | undefined;
    mocks.onDocumentEvent.mockImplementation((_event, handler) => {
      renameHandler = handler;
      return {};
    });

    installPublicationRenameAutoSync();
    renameHandler?.("document-1", "Old Title", "New Title", true);
    await Promise.resolve();

    expect(mocks.syncPublicationContent).not.toHaveBeenCalled();
  });

  it("does not sync an open published document when the join payload denies publication sync", async () => {
    const state = {
      access: { kind: "workspace" },
      canSyncPublication: true,
      lastSavedState: lastSavedState("Published body"),
      publicationState: { isPublished: false, updatedAt: null },
      workspaceId: "workspace-1",
    } as DocumentState;

    applyInitialPublicationState("document-1", state, {
      is_published: true,
      updated_at: "2026-05-01T00:00:00Z",
      can_sync: false,
    });
    queuePublicationAutoSync("document-1", state);
    await Promise.resolve();

    expect(mocks.syncPublicationContent).not.toHaveBeenCalled();
  });

  it("keeps the rename title override when headless open queues catch-up", async () => {
    let renameHandler:
      | ((documentId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void)
      | undefined;
    const state = {
      access: { kind: "workspace" },
      canSyncPublication: true,
      lastSavedState: lastSavedState("Published body"),
      publicationState: { isPublished: true, updatedAt: "2026-05-01T00:00:00Z" },
      workspaceId: "workspace-1",
    } as DocumentState;
    let resolveFirstSync: ((result: { updated_at: string }) => void) | undefined;

    mocks.onDocumentEvent.mockImplementation((_event, handler) => {
      renameHandler = handler;
      return {};
    });
    mocks.syncPublicationContent.mockImplementationOnce(() => {
      return new Promise((resolve) => {
        resolveFirstSync = resolve;
      });
    });

    installPublicationRenameAutoSync();
    renameHandler?.("document-1", "Old Title", "New Title", true);

    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalledTimes(1);
    });
    queuePublicationAutoSync("document-1", state);
    resolveFirstSync?.({ updated_at: "2026-05-02T00:00:00Z" });

    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalledTimes(2);
    });

    expect(mocks.syncPublicationContent.mock.calls.map(([, body]) => body.title)).toEqual([
      "New Title",
      "New Title",
    ]);
  });

  it("defers sync until the workspace publishing flag is known to be enabled", async () => {
    workspaceEnabledQuery(undefined);
    let renameHandler:
      | ((documentId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void)
      | undefined;
    mocks.onDocumentEvent.mockImplementation((_event, handler) => {
      renameHandler = handler;
      return {};
    });

    installPublicationRenameAutoSync();
    renameHandler?.("document-1", "Old Title", "New Title", true);
    mocks.getDocumentList.mockReturnValue([]);
    await Promise.resolve();

    expect(mocks.getWorkspace).toHaveBeenCalledWith("workspace-1");
    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalledWith(
        "document-1",
        expect.objectContaining({ title: "New Title" }),
      );
    });
  });

  it("treats missing workspace publishing flag in list cache as unknown", async () => {
    workspaceEnabledQuery(undefined, { workspaces: [{ id: "workspace-1" }] });
    let renameHandler:
      | ((documentId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void)
      | undefined;
    mocks.onDocumentEvent.mockImplementation((_event, handler) => {
      renameHandler = handler;
      return {};
    });

    installPublicationRenameAutoSync();
    renameHandler?.("document-1", "Old Title", "New Title", true);

    await vi.waitFor(() => {
      expect(mocks.getWorkspace).toHaveBeenCalledWith("workspace-1");
    });
    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalled();
    });
  });

  it("treats missing workspace publishing flag in detail cache as unknown", async () => {
    let workspace:
      | {
          id: string;
        }
      | undefined = { id: "workspace-1" };
    mocks.getQueryData.mockImplementation((key: unknown[]) => {
      if (key[0] === "workspace" && key[1] === "workspace-1") return workspace;
      return undefined;
    });
    mocks.setQueryData.mockImplementation((key: unknown[], value) => {
      if (key[0] === "workspace" && key[1] === "workspace-1") {
        workspace = value;
      }
    });
    let renameHandler:
      | ((documentId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void)
      | undefined;
    mocks.onDocumentEvent.mockImplementation((_event, handler) => {
      renameHandler = handler;
      return {};
    });

    installPublicationRenameAutoSync();
    renameHandler?.("document-1", "Old Title", "New Title", true);

    await vi.waitFor(() => {
      expect(mocks.getWorkspace).toHaveBeenCalledWith("workspace-1");
    });
    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalled();
    });
  });

  it("syncs publication immediately after save", async () => {
    const state = {
      access: { kind: "workspace" },
      canSyncPublication: true,
      lastSavedState: lastSavedState("Published body"),
      publicationState: { isPublished: true, updatedAt: "2026-05-01T00:00:00Z" },
      workspaceId: "workspace-1",
    } as DocumentState;

    queuePublicationSaveSync("document-1", state);
    queuePublicationSaveSync("document-1", state);

    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalledTimes(1);
    });
  });

  it("does not sync after workspace publishing resolves as disabled", async () => {
    workspaceEnabledQuery(undefined);
    mocks.getWorkspace.mockResolvedValue({
      id: "workspace-1",
      public_publishing_enabled: false,
    });
    let renameHandler:
      | ((documentId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void)
      | undefined;
    mocks.onDocumentEvent.mockImplementation((_event, handler) => {
      renameHandler = handler;
      return {};
    });

    installPublicationRenameAutoSync();
    renameHandler?.("document-1", "Old Title", "New Title", true);
    await vi.waitFor(() => {
      expect(mocks.getWorkspace).toHaveBeenCalledWith("workspace-1");
    });
    await Promise.resolve();

    expect(mocks.syncPublicationContent).not.toHaveBeenCalled();
  });

  it("keeps publication state when the server rejects sync because publishing is disabled", async () => {
    const state = {
      access: { kind: "workspace" },
      canSyncPublication: true,
      lastSavedState: lastSavedState("Published body"),
      publicationState: { isPublished: true, updatedAt: "2026-05-01T00:00:00Z" },
      workspaceId: "workspace-1",
    } as DocumentState;
    mocks.syncPublicationContent.mockRejectedValue(
      new mocks.ApiError(403, { error: "public_publishing_disabled" }),
    );

    queuePublicationAutoSync("document-1", state);

    await vi.waitFor(() => {
      expect(mocks.invalidateQueries).toHaveBeenCalledWith({
        queryKey: ["workspace", "workspace-1"],
      });
    });

    queuePublicationAutoSync("document-1", state);
    await Promise.resolve();

    expect(mocks.syncPublicationContent).toHaveBeenCalledTimes(1);
    expect(mocks.setDocumentPublicationState).not.toHaveBeenCalledWith(
      "document-1",
      expect.objectContaining({ isPublished: false }),
    );
  });

  it("does not restore published state when an in-flight sync completes after unpublish", async () => {
    const state = {
      access: { kind: "workspace" },
      canSyncPublication: true,
      lastSavedState: lastSavedState("Published body"),
      publicationState: { isPublished: true, updatedAt: "2026-05-01T00:00:00Z" },
      workspaceId: "workspace-1",
    } as DocumentState;
    let resolveSync: ((result: { updated_at: string }) => void) | undefined;
    mocks.syncPublicationContent.mockImplementationOnce(() => {
      return new Promise((resolve) => {
        resolveSync = resolve;
      });
    });

    queuePublicationAutoSync("document-1", state);

    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalledTimes(1);
    });

    applyPublicationStatusChanged("document-1", state, {
      is_published: false,
      updated_at: null,
    });
    resolveSync?.({ updated_at: "2026-05-02T00:00:00Z" });
    await Promise.resolve();

    expect(mocks.setDocumentPublicationState).toHaveBeenCalledWith(
      "document-1",
      expect.objectContaining({ isPublished: false }),
    );
    expect(mocks.setDocumentPublicationState).not.toHaveBeenCalledWith(
      "document-1",
      expect.objectContaining({ isPublished: true }),
    );
  });

  it("does not send content when unpublish arrives while resolving publication content", async () => {
    const state = {
      access: { kind: "workspace" },
      canSyncPublication: true,
      lastSavedState: null,
      publicationState: { isPublished: true, updatedAt: "2026-05-01T00:00:00Z" },
      workspaceId: "workspace-1",
    } as DocumentState;
    let resolveContent:
      | ((doc: { id: string; title: string; text: string; release: () => void }) => void)
      | undefined;
    mocks.getDocumentById.mockImplementationOnce(() => {
      return new Promise((resolve) => {
        resolveContent = resolve;
      });
    });

    queuePublicationAutoSync("document-1", state);
    await vi.waitFor(() => {
      expect(mocks.getDocumentById).toHaveBeenCalledWith("document-1");
    });

    applyPublicationStatusChanged("document-1", state, {
      is_published: false,
      updated_at: null,
    });
    resolveContent?.({
      id: "document-1",
      title: "Old Title",
      text: "Published body",
      release: vi.fn(),
    });
    await Promise.resolve();

    expect(mocks.syncPublicationContent).not.toHaveBeenCalled();
  });

  it("does not rerun an in-flight rename sync after unpublish", async () => {
    let renameHandler:
      | ((documentId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void)
      | undefined;
    const state = {
      access: { kind: "workspace" },
      canSyncPublication: true,
      lastSavedState: lastSavedState("Published body"),
      publicationState: { isPublished: true, updatedAt: "2026-05-01T00:00:00Z" },
      workspaceId: "workspace-1",
    } as DocumentState;
    let resolveSync: ((result: { updated_at: string }) => void) | undefined;

    mocks.onDocumentEvent.mockImplementation((_event, handler) => {
      renameHandler = handler;
      return {};
    });
    mocks.syncPublicationContent.mockImplementationOnce(() => {
      return new Promise((resolve) => {
        resolveSync = resolve;
      });
    });

    installPublicationRenameAutoSync();
    renameHandler?.("document-1", "Old Title", "New Title", true);

    await vi.waitFor(() => {
      expect(mocks.syncPublicationContent).toHaveBeenCalledTimes(1);
    });

    queuePublicationAutoSync("document-1", state);
    applyPublicationStatusChanged("document-1", state, {
      is_published: false,
      updated_at: null,
    });
    resolveSync?.({ updated_at: "2026-05-02T00:00:00Z" });
    await Promise.resolve();

    expect(mocks.syncPublicationContent).toHaveBeenCalledTimes(1);
  });
});
