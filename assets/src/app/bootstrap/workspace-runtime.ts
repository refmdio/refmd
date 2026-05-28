import { initApp } from "@/app/bootstrap/app-instance";
import { appDocuments, documentEvents, documentQueries } from "@/app/bootstrap/document-manager";
import { createWorkspaceBridge } from "@/app/bootstrap/workspace-bridge";
import { workspaceManager, type usePanelWorkspace } from "@/features/panel";
import { getActiveEditor } from "@/features/editor";
import { getStatusBarEl } from "@/widgets/document-workspace";
import type { App } from "@/shared/lib/workspace/app";

type DocumentWorkspace = ReturnType<typeof usePanelWorkspace>;

export function initializeWorkspaceRuntime(documentWorkspace: DocumentWorkspace): App {
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
  });
  workspaceManager.setAppRef(app);
  workspaceManager.setMosaicOps({
    focusPanel: (panelId) => documentWorkspace.focusPanel(panelId),
    setMosaicState: (state) => documentWorkspace.setMosaicState(state),
    mosaicState: () => documentWorkspace.mosaicState(),
    openWorkspaceTile: (panelId, documentId) =>
      documentWorkspace.openWorkspaceTile(panelId, documentId),
    closeWorkspaceTiles: (tileIds) => documentWorkspace.closeWorkspaceTiles(tileIds),
  });

  createWorkspaceBridge(workspaceManager, documentEvents, {
    focusedPanelId: () => documentWorkspace.focusedPanelId(),
    openDocuments: () => documentWorkspace.openDocuments(),
    mosaicState: () => documentWorkspace.mosaicState(),
    statusBarEl: () => getStatusBarEl(),
  });

  return app;
}
