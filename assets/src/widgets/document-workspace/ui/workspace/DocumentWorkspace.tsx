import { Show, createEffect, createMemo, createSignal } from "solid-js";
import { Mosaic } from "solid-mosaic-component";
import type { MosaicBranch } from "solid-mosaic-component";
import { FileTextIcon } from "lucide-solid";
import { useDocuments, useDocumentTitles } from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { OfflineIndicator } from "@/features/editor";
import { decodePanelId, decodeWorkspacePluginTileId, usePanelWorkspace } from "@/features/panel";
import {
  auxiliaryPanePreferredLocation,
  type AuxiliaryPaneLocation,
} from "@/shared/lib/workspace/app";
import { workspaceManager } from "@/features/panel";
import { CustomTile } from "../tile/CustomTile";
import { DocumentTile } from "../tile/DocumentTile";
import { PluginWorkspaceTile } from "../tile/PluginWorkspaceTile";
import { AuxiliaryPaneColumn } from "./AuxiliaryPaneColumn";

import "solid-mosaic-component/solid-mosaic-component.css";
import "./mosaic-theme.css";

const [statusBarEl, setStatusBarEl] = createSignal<HTMLDivElement | null>(null);

export function getStatusBarEl(): HTMLDivElement | null {
  return statusBarEl();
}

interface DocumentWorkspaceProps {
  workspaceId?: string | null;
  useCurrentWorkspaceId?: boolean;
}

export function DocumentWorkspace(props: DocumentWorkspaceProps = {}) {
  const workspace = usePanelWorkspace();
  const workspaceId = () => {
    if (props.useCurrentWorkspaceId === false) {
      return props.workspaceId ?? null;
    }

    return props.workspaceId ?? currentWorkspaceId();
  };
  const { flatDocuments } = useDocuments(workspaceId);
  const { getTitle: getTitleFromDoc } = useDocumentTitles(flatDocuments, workspaceId);
  const auxiliaryPanesByLocation = (location: AuxiliaryPaneLocation) =>
    workspaceManager
      .getAuxiliaryPanes()
      .filter((pane) => auxiliaryPanePreferredLocation(pane) === location);
  const leftAuxiliaryPanes = createMemo(() => auxiliaryPanesByLocation("left"));
  const documentLeftAuxiliaryPanes = createMemo(() => auxiliaryPanesByLocation("document_left"));
  const documentRightAuxiliaryPanes = createMemo(() => auxiliaryPanesByLocation("document_right"));
  const rightAuxiliaryPanes = createMemo(() => auxiliaryPanesByLocation("right"));
  const [focusedAuxiliaryPaneId, setFocusedAuxiliaryPaneId] = createSignal<string | null>(null);
  const [auxiliaryPaneWidths, setAuxiliaryPaneWidths] = createSignal<
    Partial<Record<AuxiliaryPaneLocation, number>>
  >({});

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
      if (decodeWorkspacePluginTileId(panelId)) {
        return <PluginWorkspaceTile panelId={panelId} path={path} workspace={workspace} />;
      }
      const leaf = workspaceManager.getLeafById(panelId);
      if (leaf?.view) return <CustomTile panelId={panelId} path={path} workspace={workspace} />;
      return <div />;
    }

    const target = workspace.openDocuments().get(panel.targetKey);
    const doc = flatDocuments().find((d) => d.id === panel.documentId);
    const title = doc ? getTitleFromDoc(doc) : (target?.title ?? "Untitled");

    return (
      <DocumentTile
        panelId={panelId}
        panel={panel}
        path={path}
        title={title}
        archivedAt={doc?.archived_at}
        workspace={workspace}
        workspaceId={target?.workspaceId ?? workspaceId()}
      />
    );
  };

  return (
    <div class="h-full flex flex-col">
      <div class="flex min-h-0 flex-1 overflow-hidden">
        <AuxiliaryPaneColumn
          location="left"
          panes={leftAuxiliaryPanes()}
          focusedPaneId={focusedAuxiliaryPaneId()}
          setFocusedPaneId={setFocusedAuxiliaryPaneId}
          width={auxiliaryPaneWidths().left}
          setWidth={(width) => setAuxiliaryPaneWidths((current) => ({ ...current, left: width }))}
        />
        <div class="min-w-0 flex-1 overflow-hidden">
          <div class="flex h-full min-w-0 overflow-hidden">
            <AuxiliaryPaneColumn
              location="document_left"
              panes={documentLeftAuxiliaryPanes()}
              focusedPaneId={focusedAuxiliaryPaneId()}
              setFocusedPaneId={setFocusedAuxiliaryPaneId}
              width={auxiliaryPaneWidths().document_left}
              setWidth={(width) =>
                setAuxiliaryPaneWidths((current) => ({ ...current, document_left: width }))
              }
            />
            <div class="min-w-0 flex-1 overflow-hidden">
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
            <AuxiliaryPaneColumn
              location="document_right"
              panes={documentRightAuxiliaryPanes()}
              focusedPaneId={focusedAuxiliaryPaneId()}
              setFocusedPaneId={setFocusedAuxiliaryPaneId}
              width={auxiliaryPaneWidths().document_right}
              setWidth={(width) =>
                setAuxiliaryPaneWidths((current) => ({ ...current, document_right: width }))
              }
            />
          </div>
        </div>
        <AuxiliaryPaneColumn
          location="right"
          panes={rightAuxiliaryPanes()}
          focusedPaneId={focusedAuxiliaryPaneId()}
          setFocusedPaneId={setFocusedAuxiliaryPaneId}
          width={auxiliaryPaneWidths().right}
          setWidth={(width) => setAuxiliaryPaneWidths((current) => ({ ...current, right: width }))}
        />
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
