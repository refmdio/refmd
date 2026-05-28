import type { MosaicNode } from "solid-mosaic-component";
import { findFirstDocumentResourcePanelId, hasDocumentResourcePanels } from "./panel-utils";

interface WorkspaceTileWorkspace {
  mosaicState: () => MosaicNode<string> | null;
  closePanel: (panelId: string) => void;
}

export function closeWorkspaceTiles(workspace: WorkspaceTileWorkspace, documentId: string): void {
  const state = workspace.mosaicState();
  if (!state || !hasDocumentResourcePanels(state, documentId)) return;

  let panelId = findFirstDocumentResourcePanelId(state, documentId);
  while (panelId) {
    workspace.closePanel(panelId);
    const next = workspace.mosaicState();
    panelId = next ? findFirstDocumentResourcePanelId(next, documentId) : null;
  }
}
