import type { MosaicNode } from "solid-mosaic-component";
import { findFirstPanelId, hasDocumentPanels } from "./panel-utils";

interface DocumentPanelWorkspace {
  mosaicState: () => MosaicNode<string> | null;
  closePanel: (panelId: string) => void;
}

export function closeDocumentPanels(workspace: DocumentPanelWorkspace, documentId: string): void {
  const state = workspace.mosaicState();
  if (!state || !hasDocumentPanels(state, documentId)) return;

  let panelId = findFirstPanelId(state, documentId);
  while (panelId) {
    workspace.closePanel(panelId);
    const next = workspace.mosaicState();
    panelId = next ? findFirstPanelId(next, documentId) : null;
  }
}
