import { Show, createEffect, createSignal } from "solid-js";
import { Mosaic } from "solid-mosaic-component";
import type { MosaicBranch } from "solid-mosaic-component";
import { FileTextIcon } from "lucide-solid";
import { useDocuments, useDocumentTitles } from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { OfflineIndicator } from "@/features/editor";
import { decodePanelId, usePanelWorkspace } from "@/features/panel";
import { workspaceManager } from "@/features/panel";
import { CustomTile } from "./CustomTile";
import { DocumentTile } from "./DocumentTile";

import "solid-mosaic-component/solid-mosaic-component.css";
import "./mosaic-theme.css";

const [statusBarEl, setStatusBarEl] = createSignal<HTMLDivElement | null>(null);

export function getStatusBarEl(): HTMLDivElement | null {
  return statusBarEl();
}

export function DocumentWorkspace() {
  const workspace = usePanelWorkspace();
  const workspaceId = () => currentWorkspaceId();
  const { flatDocuments } = useDocuments(workspaceId);
  const { getTitle: getTitleFromDoc } = useDocumentTitles(flatDocuments, workspaceId);

  createEffect(() => {
    const pid = workspace.focusedPanelId();
    if (!pid) return;
    const el = document.querySelector<HTMLElement>(`[data-panel-id="${pid}"]`);
    if (el && !el.contains(document.activeElement)) {
      const focusable = el.querySelector<HTMLElement>(".cm-content, .ProseMirror");
      focusable?.focus();
    }
  });

  const renderTile = (panelId: string, path: MosaicBranch[]) => {
    const panel = decodePanelId(panelId);

    if (!panel) {
      const leaf = workspaceManager.getLeafById(panelId);
      if (leaf?.view) return <CustomTile panelId={panelId} path={path} workspace={workspace} />;
      return <div />;
    }

    const doc = flatDocuments().find((d) => d.id === panel.documentId);
    const title = doc ? getTitleFromDoc(doc) : "Untitled";

    return (
      <DocumentTile
        panelId={panelId}
        panel={panel}
        path={path}
        title={title}
        archivedAt={doc?.archived_at}
        workspace={workspace}
      />
    );
  };

  return (
    <div class="h-full flex flex-col">
      <div class="flex-1 overflow-hidden">
        <Show
          when={workspace.mosaicState()}
          fallback={
            <div class="flex items-center justify-center h-full text-muted-foreground">
              <div class="text-center">
                <FileTextIcon class="size-12 mx-auto mb-4 opacity-50" />
                <p>No documents open</p>
                <p class="text-sm">Select a document from the sidebar or drag one here</p>
              </div>
            </div>
          }
        >
          <Mosaic<string>
            renderTile={renderTile}
            value={workspace.mosaicState()}
            onChange={workspace.handleMosaicChange}
            className="mosaic-blueprint-theme"
          />
        </Show>
      </div>
      <div
        ref={setStatusBarEl}
        class="flex items-center gap-3 px-2 py-0.5 text-xs text-muted-foreground border-t border-border shrink-0"
        classList={{ hidden: !workspace.mosaicState() }}
      >
        <OfflineIndicator />
      </div>
    </div>
  );
}
