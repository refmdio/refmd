import { createEffect, onCleanup } from "solid-js";

export interface BridgeSources {
  focusedPanelId: () => string | null;
  openDocuments: () => Map<string, { title?: string }>;
  mosaicState: () => any;
  statusBarEl: () => HTMLElement | null;
}

interface WorkspaceSink {
  setActiveLeafById(panelId: string): void;
  trigger(name: string, ...data: unknown[]): void;
  syncMosaicLeaves(state: any): void;
  setStatusBarContainer(el: HTMLElement | null): void;
}

interface DocumentSink {
  notifyDocumentOpen(docId: string, title: string): void;
  notifyDocumentClose(docId: string): void;
}

export function createWorkspaceBridge(
  workspace: WorkspaceSink,
  documents: DocumentSink,
  sources: BridgeSources,
): void {
  // 1. Focused panel → active leaf
  createEffect(() => {
    const pid = sources.focusedPanelId();
    workspace.setActiveLeafById(pid ?? "");
  });

  // 2. Open documents → document-open / document-close events
  let prevOpenDocIds = new Set<string>();
  createEffect(() => {
    const currentDocs = sources.openDocuments();
    const currentIds = new Set(currentDocs.keys());

    for (const id of currentIds) {
      if (!prevOpenDocIds.has(id)) {
        const doc = currentDocs.get(id);
        documents.notifyDocumentOpen(id, doc?.title ?? "Untitled");
      }
    }
    for (const id of prevOpenDocIds) {
      if (!currentIds.has(id)) {
        documents.notifyDocumentClose(id);
      }
    }
    prevOpenDocIds = currentIds;
  });

  // 3. Mosaic state → layout-change event + leaf sync
  createEffect(() => {
    const state = sources.mosaicState();
    workspace.trigger("layout-change");
    workspace.syncMosaicLeaves(state);
  });

  // 4. Status bar container binding
  createEffect(() => {
    const el = sources.statusBarEl();
    workspace.setStatusBarContainer(el);
  });

  // 5. Window resize → resize event
  const handleResize = () => workspace.trigger("resize");
  window.addEventListener("resize", handleResize);
  onCleanup(() => window.removeEventListener("resize", handleResize));

  // 6. CSS class change (dark mode) → css-change event
  const cssObserver = new MutationObserver(() => workspace.trigger("css-change"));
  cssObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
  onCleanup(() => cssObserver.disconnect());
}
