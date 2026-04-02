import { onCleanup } from "solid-js";
import { useNavigate } from "@solidjs/router";
import type { QueryClient } from "@tanstack/solid-query";
import { currentWorkspaceId } from "@/entities/workspace";
import { attachActiveLeafRouteSync, usePanelWorkspace, workspaceManager } from "@/features/panel";
import {
  acquireDocumentState,
  getActiveEditor,
  getDocumentState,
  getDocText,
  getEditorForDocument,
  initializeDocumentSync,
  releaseDocumentState,
  setFocusedPanelIdAccessor,
  setOnEditorRegistered,
} from "@/features/editor";
import { initApp } from "@/app/bootstrap/app-instance";
import { getStatusBarEl } from "@/widgets/document-workspace";
import type { App } from "@/shared/lib/app-context";
import { documentNavigation } from "@/entities/document";
import {
  appDocuments,
  documentCommands,
  documentEvents,
  documentQueries,
  documentRuntime,
} from "@/app/bootstrap/document-manager";
import { createWorkspaceBridge } from "@/app/bootstrap/workspace-bridge";

type DocumentWorkspace = ReturnType<typeof usePanelWorkspace>;
type EditorDocumentState = NonNullable<ReturnType<typeof getDocumentState>>;
type Navigate = ReturnType<typeof useNavigate>;

export function useDocumentWorkspaceRuntime(
  documentWorkspace: DocumentWorkspace,
  navigate: Navigate,
  queryClient: QueryClient,
): App {
  setFocusedPanelIdAccessor(() => documentWorkspace.focusedPanelId());
  setOnEditorRegistered(() => documentEvents.flushPendingOpens());
  documentNavigation.init((documentId) =>
    navigate(documentId ? `/document/${documentId}` : "/dashboard", {
      replace: true,
      scroll: false,
    }),
  );

  documentRuntime.init(
    {
      focusedDocumentId: () => documentWorkspace.focusedDocumentId(),
    },
    queryClient,
    () => currentWorkspaceId(),
    () => getActiveEditor(),
    (docId) => getEditorForDocument(docId),
    {
      acquireDocumentState,
      getDocumentState,
      releaseDocumentState,
      initializeDocumentSync: (documentId, workspaceId, state) =>
        initializeDocumentSync(documentId, workspaceId, state as EditorDocumentState),
    },
  );
  documentRuntime.setDocTextResolver((id) => getDocText(id));
  documentRuntime.setCreateDocumentFn(async (wsId, title, parentId) => {
    try {
      const { createDocument } = await import("@/features/document");
      return await createDocument(wsId, title, parentId);
    } catch (err) {
      // Only fall back to offline creation on network errors, not auth/permission errors
      if (err instanceof TypeError) {
        const { createDocumentOffline } = await import("@/features/editor");
        return createDocumentOffline(wsId, parentId, title);
      }
      throw err;
    }
  });

  workspaceManager.init();
  workspaceManager.setEditorContextResolver(() => {
    const editor = getActiveEditor();
    const doc = documentQueries.getActiveDocument();
    if (!editor || !doc) return null;
    return { editor, doc };
  });
  workspaceManager.setActiveDocumentResolver(() => documentQueries.getActiveDocument());

  const app = initApp(workspaceManager, {
    documents: appDocuments,
    documentCommands,
    documentEvents,
    documentQueries,
    documentRuntime,
  });
  workspaceManager.setAppRef(app);
  workspaceManager.setMosaicOps({
    focusPanel: (panelId) => documentWorkspace.focusPanel(panelId),
    setMosaicState: (state) => documentWorkspace.setMosaicState(state),
    mosaicState: () => documentWorkspace.mosaicState(),
  });

  createWorkspaceBridge(workspaceManager, documentEvents, {
    focusedPanelId: () => documentWorkspace.focusedPanelId(),
    openDocuments: () => documentWorkspace.openDocuments(),
    mosaicState: () => documentWorkspace.mosaicState(),
    statusBarEl: () => getStatusBarEl(),
  });

  onCleanup(attachActiveLeafRouteSync(navigate, () => documentWorkspace.openDocuments()));

  return app;
}
