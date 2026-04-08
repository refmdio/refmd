import { Show, Suspense, lazy } from "solid-js";
import type { MosaicBranch } from "solid-mosaic-component";
import { MosaicWindow } from "solid-mosaic-component";
import { Columns2Icon, MoreVerticalIcon, RefreshCwIcon, SplitIcon, XIcon } from "lucide-solid";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";
import {
  getDocumentAwareness,
  getDocumentState,
  getEditor,
  PresenceAvatars,
} from "@/features/editor";
import {
  decodePanelId,
  hasScrollGroupPeer,
  workspaceManager,
  type usePanelWorkspace,
} from "@/features/panel";
import { getDocumentEvents } from "@/shared/lib/document/manager";
import { DocumentPanelShell } from "./DocumentPanelShell";
import { Spinner } from "@/shared/ui/spinner";

type Workspace = ReturnType<typeof usePanelWorkspace>;

interface PanelRef {
  documentId: string;
  type: "markdown" | "wysiwyg";
  scrollGroupId: string;
}

interface DocumentTileProps {
  panelId: string;
  panel: PanelRef;
  path: MosaicBranch[];
  title: string;
  archivedAt?: string | null;
  workspace: Workspace;
}

const CodeMirrorEditorImpl = lazy(async () => {
  const mod = await import("@/features/editor/ui/editors/CodeMirrorEditor");
  return { default: mod.CodeMirrorEditor };
});

const ProseMirrorEditorImpl = lazy(async () => {
  const mod = await import("@/features/editor/ui/editors/ProseMirrorEditor");
  return { default: mod.ProseMirrorEditor };
});

function EditorFallback() {
  return (
    <div class="flex h-full items-center justify-center bg-background">
      <Spinner class="size-6" />
    </div>
  );
}

export function DocumentTile(props: DocumentTileProps) {
  const documentEvents = getDocumentEvents();
  const isMarkdown = () => props.panel.type === "markdown";
  const readOnly = () => !!props.archivedAt || getDocumentState(props.panel.documentId)?.readOnly;
  const panelLabel = () => (isMarkdown() ? "Markdown" : "WYSIWYG");
  const isAlreadySplit = () => {
    const state = props.workspace.mosaicState();
    return state ? hasScrollGroupPeer(state, props.panel.scrollGroupId, props.panelId) : false;
  };
  const getDocumentEventContext = () => {
    const editor = getEditor(props.panelId);
    return {
      editor,
      documentView: {
        id: props.panel.documentId,
        title: props.title,
        editor,
      },
    };
  };
  const handleDocChange = () => {
    const { editor, documentView } = getDocumentEventContext();
    documentEvents.notifyDocumentChangeFor(props.panel.documentId, editor);
    workspaceManager.trigger("editor-change", editor, documentView);
  };
  const handleEditorPaste = (evt: ClipboardEvent) => {
    const { editor, documentView } = getDocumentEventContext();
    workspaceManager.trigger("editor-paste", evt, editor, documentView);
  };
  const handleEditorDrop = (evt: DragEvent) => {
    const { editor, documentView } = getDocumentEventContext();
    workspaceManager.trigger("editor-drop", evt, editor, documentView);
  };
  const editorProps = () => ({
    documentId: props.panel.documentId,
    panelId: props.panelId,
    scrollGroupId: props.panel.scrollGroupId,
    readOnly: readOnly(),
    onDocChange: handleDocChange,
    onEditorPaste: handleEditorPaste,
    onEditorDrop: handleEditorDrop,
  });

  return (
    <MosaicWindow<string>
      title={`${props.title} - ${panelLabel()}`}
      path={props.path}
      onDragStart={() => props.workspace.focusPanel(props.panelId)}
      toolbarControls={
        <div class="flex items-center">
          <Show when={props.workspace.focusedPanelId() === props.panelId}>
            <PresenceAvatars awareness={getDocumentAwareness(props.panel.documentId)} />
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
              <DropdownMenuItem onClick={() => props.workspace.splitPanel(props.panelId, "row")}>
                <Columns2Icon class="size-4 mr-2" />
                Split Horizontal
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => props.workspace.splitPanel(props.panelId, "column")}>
                <SplitIcon class="size-4 mr-2" />
                Split Vertical
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <Show
                when={isAlreadySplit()}
                fallback={
                  <>
                    <DropdownMenuItem
                      onClick={() => props.workspace.switchPanelType(props.panelId)}
                    >
                      <RefreshCwIcon class="size-4 mr-2" />
                      Switch to {isMarkdown() ? "WYSIWYG" : "Markdown"}
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => props.workspace.switchToSplit(props.panelId)}>
                      <Columns2Icon class="size-4 mr-2" />
                      Switch to Split
                    </DropdownMenuItem>
                  </>
                }
              >
                <DropdownMenuItem
                  onClick={() => props.workspace.collapseSplitTo(props.panelId, "markdown")}
                >
                  <RefreshCwIcon class="size-4 mr-2" />
                  Markdown only
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => props.workspace.collapseSplitTo(props.panelId, "wysiwyg")}
                >
                  <RefreshCwIcon class="size-4 mr-2" />
                  WYSIWYG only
                </DropdownMenuItem>
              </Show>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => props.workspace.closePanel(props.panelId)}>
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
            const focusedId = props.workspace.focusedPanelId();
            if (focusedId === props.panelId) return false;
            if (!focusedId) return true;
            const focusedPanel = decodePanelId(focusedId);
            if (!focusedPanel) return true;
            return (
              focusedPanel.type !== props.panel.type ||
              focusedPanel.documentId !== props.panel.documentId
            );
          })(),
        }}
        data-panel-id={props.panelId}
        onFocusIn={() => props.workspace.focusPanel(props.panelId)}
        onMouseDown={() => props.workspace.focusPanel(props.panelId)}
        onContextMenu={() => {
          const editor = getEditor(props.panelId);
          if (editor) {
            workspaceManager.trigger("editor-menu", null, editor, {
              id: props.panel.documentId,
              title: props.title,
              editor,
            });
          }
        }}
      >
        <DocumentPanelShell documentId={props.panel.documentId}>
          <Suspense fallback={<EditorFallback />}>
            {isMarkdown() ? (
              <CodeMirrorEditorImpl {...editorProps()} />
            ) : (
              <ProseMirrorEditorImpl {...editorProps()} />
            )}
          </Suspense>
        </DocumentPanelShell>
      </div>
    </MosaicWindow>
  );
}
