import { Show, createEffect } from "solid-js";
import { Mosaic, MosaicWindow } from "solid-mosaic-component";
import type { MosaicBranch } from "solid-mosaic-component";
import {
  FileTextIcon,
  MoreVerticalIcon,
  SplitIcon,
  Columns2Icon,
  RefreshCwIcon,
  XIcon,
} from "lucide-solid";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";
import { useDocuments, useDocumentTitles } from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { decodePanelId, usePanelWorkspace, hasScrollGroupPeer } from "@/features/panel";
import { CodeMirrorEditor, ProseMirrorEditor } from "@/features/editor";
import { DocumentPanelShell } from "./DocumentPanelShell";

import "solid-mosaic-component/solid-mosaic-component.css";
import "./mosaic-theme.css";

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
    if (!panel) return <div />;

    const doc = flatDocuments().find((d) => d.id === panel.documentId);
    const title = doc ? getTitleFromDoc(doc) : "Untitled";
    const isMarkdown = panel.type === "markdown";
    const isArchived = !!doc?.archived_at;
    const panelLabel = isMarkdown ? "Markdown" : "WYSIWYG";
    const isAlreadySplit = () => {
      const state = workspace.mosaicState();
      return state ? hasScrollGroupPeer(state, panel.scrollGroupId, panelId) : false;
    };

    return (
      <MosaicWindow<string>
        title={`${title} - ${panelLabel}`}
        path={path}
        onDragStart={() => workspace.focusPanel(panelId)}
        toolbarControls={
          <DropdownMenu>
            <DropdownMenuTrigger
              as="button"
              class="p-1 hover:bg-muted rounded"
              onClick={(e: MouseEvent) => e.stopPropagation()}
            >
              <MoreVerticalIcon class="size-4" />
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={() => workspace.splitPanel(panelId, "row")}>
                <Columns2Icon class="size-4 mr-2" />
                Split Horizontal
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => workspace.splitPanel(panelId, "column")}>
                <SplitIcon class="size-4 mr-2" />
                Split Vertical
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <Show
                when={isAlreadySplit()}
                fallback={
                  <>
                    <DropdownMenuItem onClick={() => workspace.switchPanelType(panelId)}>
                      <RefreshCwIcon class="size-4 mr-2" />
                      Switch to {isMarkdown ? "WYSIWYG" : "Markdown"}
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => workspace.switchToSplit(panelId)}>
                      <Columns2Icon class="size-4 mr-2" />
                      Switch to Split
                    </DropdownMenuItem>
                  </>
                }
              >
                <DropdownMenuItem onClick={() => workspace.collapseSplitTo(panelId, "markdown")}>
                  <RefreshCwIcon class="size-4 mr-2" />
                  Markdown only
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => workspace.collapseSplitTo(panelId, "wysiwyg")}>
                  <RefreshCwIcon class="size-4 mr-2" />
                  WYSIWYG only
                </DropdownMenuItem>
              </Show>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => workspace.closePanel(panelId)}>
                <XIcon class="size-4 mr-2" />
                Close
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        }
      >
        <div
          class="h-full"
          data-panel-id={panelId}
          onFocusIn={() => workspace.focusPanel(panelId)}
          onMouseDown={() => workspace.focusPanel(panelId)}
        >
          <DocumentPanelShell documentId={panel.documentId}>
            {isMarkdown ? (
              <CodeMirrorEditor
                documentId={panel.documentId}
                scrollGroupId={panel.scrollGroupId}
                readOnly={isArchived}
              />
            ) : (
              <ProseMirrorEditor
                documentId={panel.documentId}
                scrollGroupId={panel.scrollGroupId}
                readOnly={isArchived}
              />
            )}
          </DocumentPanelShell>
        </div>
      </MosaicWindow>
    );
  };

  return (
    <Show
      when={workspace.mosaicState()}
      fallback={
        <div class="flex items-center justify-center h-full text-muted-foreground">
          <div class="text-center">
            <FileTextIcon class="size-12 mx-auto mb-4 opacity-50" />
            <p>No documents open</p>
            <p class="text-sm">Select a document from the sidebar</p>
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
  );
}
