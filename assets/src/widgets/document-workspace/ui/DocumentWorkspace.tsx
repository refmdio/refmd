import { Show, createEffect, createSignal, onCleanup, onMount } from "solid-js";
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
import { useDocuments, useDocumentTitles, setTileDropHandler } from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { OfflineIndicator } from "@/features/editor";
import { setupFlushHooks } from "@/features/editor";
import { decodePanelId, usePanelWorkspace, hasScrollGroupPeer } from "@/features/panel";
import { documentEvents, documentRuntime } from "@/shared/lib/document-manager";
import { workspaceManager } from "@/features/panel";
import {
  getEditor,
  getDocumentState,
  CodeMirrorEditor,
  ProseMirrorEditor,
  PresenceAvatars,
  getDocumentAwareness,
} from "@/features/editor";
import { DocumentPanelShell } from "./DocumentPanelShell";

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
  const { getTitle: getTitleFromDoc, isTitleReady } = useDocumentTitles(flatDocuments, workspaceId);

  onMount(() => {
    const cleanup = setupFlushHooks();
    onCleanup(cleanup);
  });

  documentRuntime.setTitleResolver((doc) => {
    const found = flatDocuments().find((d) => d.id === doc.id);
    return found ? getTitleFromDoc(found) : "Untitled";
  });

  createEffect(() => {
    const pid = workspace.focusedPanelId();
    if (!pid) return;
    const el = document.querySelector<HTMLElement>(`[data-panel-id="${pid}"]`);
    if (el && !el.contains(document.activeElement)) {
      const focusable = el.querySelector<HTMLElement>(".cm-content, .ProseMirror");
      focusable?.focus();
    }
  });

  setTileDropHandler((docId: string) => {
    const doc = flatDocuments().find((d) => d.id === docId);
    if (doc && doc.doc_type === "document" && isTitleReady(doc)) {
      workspace.addToTile({ id: doc.id, title: getTitleFromDoc(doc) });
    }
  });
  onCleanup(() => setTileDropHandler(null));

  const renderTile = (panelId: string, path: MosaicBranch[]) => {
    const panel = decodePanelId(panelId);

    // Custom view leaf (non-document panel)
    if (!panel) {
      const leaf = workspaceManager.getLeafById(panelId);
      if (leaf?.view) {
        return (
          <MosaicWindow<string>
            title={leaf.getDisplayText()}
            path={path}
            onDragStart={() => workspace.focusPanel(panelId)}
            toolbarControls={<div />}
          >
            <div
              class="h-full"
              data-panel-id={panelId}
              onFocusIn={() => workspace.focusPanel(panelId)}
              onMouseDown={() => workspace.focusPanel(panelId)}
              ref={(el) => {
                if (leaf.view?.containerEl && !el.contains(leaf.view.containerEl)) {
                  el.appendChild(leaf.view.containerEl);
                }
              }}
            />
          </MosaicWindow>
        );
      }
      return <div />;
    }
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
          <div class="flex items-center">
            <Show when={workspace.focusedPanelId() === panelId}>
              <PresenceAvatars awareness={getDocumentAwareness(panel.documentId)} />
            </Show>
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
          </div>
        }
      >
        <div
          class="h-full"
          classList={{
            "hide-remote-cursors": (() => {
              const focusedId = workspace.focusedPanelId();
              if (focusedId === panelId) return false;
              if (!focusedId) return true;
              const focusedPanel = decodePanelId(focusedId);
              if (!focusedPanel) return true;
              return (
                focusedPanel.type !== panel.type || focusedPanel.documentId !== panel.documentId
              );
            })(),
          }}
          data-panel-id={panelId}
          onFocusIn={() => workspace.focusPanel(panelId)}
          onMouseDown={() => workspace.focusPanel(panelId)}
          onContextMenu={(_e: MouseEvent) => {
            const editor = getEditor(panelId);
            if (editor) {
              workspaceManager.trigger("editor-menu", null, editor, {
                id: panel.documentId,
                title,
                editor,
              });
            }
          }}
        >
          <DocumentPanelShell documentId={panel.documentId}>
            {isMarkdown ? (
              <CodeMirrorEditor
                documentId={panel.documentId}
                panelId={panelId}
                scrollGroupId={panel.scrollGroupId}
                readOnly={isArchived || getDocumentState(panel.documentId)?.readOnly}
                onDocChange={() => {
                  const editor = getEditor(panelId);
                  documentEvents.notifyDocumentChangeFor(panel.documentId, editor);
                  workspaceManager.trigger("editor-change", editor, {
                    id: panel.documentId,
                    title,
                    editor,
                  });
                }}
                onEditorPaste={(evt) => {
                  const editor = getEditor(panelId);
                  workspaceManager.trigger("editor-paste", evt, editor, {
                    id: panel.documentId,
                    title,
                    editor,
                  });
                }}
                onEditorDrop={(evt) => {
                  const editor = getEditor(panelId);
                  workspaceManager.trigger("editor-drop", evt, editor, {
                    id: panel.documentId,
                    title,
                    editor,
                  });
                }}
              />
            ) : (
              <ProseMirrorEditor
                documentId={panel.documentId}
                panelId={panelId}
                scrollGroupId={panel.scrollGroupId}
                readOnly={isArchived || getDocumentState(panel.documentId)?.readOnly}
                onDocChange={() => {
                  const editor = getEditor(panelId);
                  documentEvents.notifyDocumentChangeFor(panel.documentId, editor);
                  workspaceManager.trigger("editor-change", editor, {
                    id: panel.documentId,
                    title,
                    editor,
                  });
                }}
                onEditorPaste={(evt) => {
                  const editor = getEditor(panelId);
                  workspaceManager.trigger("editor-paste", evt, editor, {
                    id: panel.documentId,
                    title,
                    editor,
                  });
                }}
                onEditorDrop={(evt) => {
                  const editor = getEditor(panelId);
                  workspaceManager.trigger("editor-drop", evt, editor, {
                    id: panel.documentId,
                    title,
                    editor,
                  });
                }}
              />
            )}
          </DocumentPanelShell>
        </div>
      </MosaicWindow>
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
