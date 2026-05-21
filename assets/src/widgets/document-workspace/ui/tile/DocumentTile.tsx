import { Show, Suspense, createEffect, lazy, onCleanup } from "solid-js";
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
  getDocumentError,
  getDocumentReadOnly,
  getDocumentSyncPaused,
  getDocumentState,
  getEditor,
  canBufferDisconnectedChanges,
  retainUxLimitNotice,
  PresenceAvatars,
} from "@/features/editor";
import {
  decodePanelId,
  hasScrollGroupPeer,
  workspaceManager,
  type usePanelWorkspace,
} from "@/features/panel";
import { getDocumentEvents } from "@/shared/lib/document/manager";
import { offlineReason } from "@/shared/lib/offline/offline-state";
import { DocumentPanelShell } from "../panel/DocumentPanelShell";
import { Spinner } from "@/shared/ui/spinner";

type Workspace = ReturnType<typeof usePanelWorkspace>;

interface PanelRef {
  source: "document" | "share-link-document" | "mounted-share-document";
  targetKey: string;
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
  workspaceId?: string | null;
}

const CodeMirrorEditorImpl = lazy(async () => {
  const mod = await import("@/widgets/document-editor");
  return { default: mod.CodeMirrorEditor };
});

const ProseMirrorEditorImpl = lazy(async () => {
  const mod = await import("@/widgets/document-editor");
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
  let syncLimitNoticeRelease: (() => void) | null = null;
  let syncLimitNoticeId: string | null = null;
  const isMarkdown = () => props.panel.type === "markdown";
  const syncLimitNotice = () => {
    const state = getDocumentState(props.panel.targetKey);
    if (!state?.initialized) return null;
    const reason = offlineReason();
    if (reason === "network") return null;
    if (reason === "auth_backoff") {
      return {
        id: `document-sync-limit:${props.panel.targetKey}:auth_backoff`,
        message: "Editing is paused while sync backs off.",
        description: "The server asked the client to slow down. Editing will resume automatically.",
      };
    }
    if (reason === "server_unreachable" || reason === "ws_disconnect") {
      if (canBufferDisconnectedChanges(state)) return null;
      return {
        id: `document-sync-limit:${props.panel.targetKey}:connection`,
        message: "Editing is paused until sync reconnects.",
        description:
          "The document cannot safely buffer more changes in this state. Editing will resume automatically.",
      };
    }
    if (getDocumentSyncPaused(props.panel.targetKey) || !state?.initialized) {
      return {
        id: `document-sync-limit:${props.panel.targetKey}:sync_ready`,
        message: "Editing is paused while the document connects.",
        description: "The editor is waiting for the document sync channel to become ready.",
      };
    }
    return null;
  };
  const syncPauseReadOnly = () => {
    const state = getDocumentState(props.panel.targetKey);
    const reason = offlineReason();
    if (reason === "network") return false;
    if (reason === "server_unreachable" || reason === "ws_disconnect") {
      return !canBufferDisconnectedChanges(state);
    }
    if (reason === "auth_backoff") return true;
    if (getDocumentSyncPaused(props.panel.targetKey)) return true;
    return !state?.initialized;
  };
  const permissionReadOnly = () => {
    getDocumentReadOnly(props.panel.targetKey);
    return !!getDocumentState(props.panel.targetKey)?.readOnly;
  };
  const readOnly = () =>
    !!props.archivedAt ||
    !!getDocumentError(props.panel.targetKey) ||
    syncPauseReadOnly() ||
    permissionReadOnly();

  const clearSyncLimitNotice = () => {
    syncLimitNoticeRelease?.();
    syncLimitNoticeRelease = null;
    syncLimitNoticeId = null;
  };

  createEffect(() => {
    const notice = syncLimitNotice();
    if (!notice) {
      clearSyncLimitNotice();
      return;
    }
    if (syncLimitNoticeId === notice.id) return;
    clearSyncLimitNotice();
    syncLimitNoticeId = notice.id;
    syncLimitNoticeRelease = retainUxLimitNotice(notice.id, notice.message, notice.description);
  });

  onCleanup(clearSyncLimitNotice);
  const panelLabel = () => (isMarkdown() ? "Markdown" : "WYSIWYG");
  const isAlreadySplit = () => {
    const state = props.workspace.mosaicState();
    return state ? hasScrollGroupPeer(state, props.panel.scrollGroupId, props.panelId) : false;
  };
  const canClose = () => true;
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
  return (
    <MosaicWindow<string>
      title={`${props.title} - ${panelLabel()}`}
      path={props.path}
      onDragStart={() => props.workspace.focusPanel(props.panelId)}
      toolbarControls={
        <div class="flex items-center">
          <Show when={props.workspace.focusedPanelId() === props.panelId}>
            <PresenceAvatars awareness={getDocumentAwareness(props.panel.targetKey)} />
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
              <Show when={canClose()}>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => props.workspace.closePanel(props.panelId)}>
                  <XIcon class="size-4 mr-2" />
                  Close
                </DropdownMenuItem>
              </Show>
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
        <DocumentPanelShell
          documentId={props.panel.documentId}
          showDialogs={props.workspace.focusedPanelId() === props.panelId}
          stateKey={props.panel.targetKey}
          workspaceId={props.workspaceId}
        >
          <Suspense fallback={<EditorFallback />}>
            {isMarkdown() ? (
              <CodeMirrorEditorImpl
                documentId={props.panel.documentId}
                stateKey={props.panel.targetKey}
                panelId={props.panelId}
                scrollGroupId={props.panel.scrollGroupId}
                readOnly={readOnly()}
                onDocChange={handleDocChange}
                onEditorPaste={handleEditorPaste}
                onEditorDrop={handleEditorDrop}
              />
            ) : (
              <ProseMirrorEditorImpl
                documentId={props.panel.documentId}
                stateKey={props.panel.targetKey}
                panelId={props.panelId}
                scrollGroupId={props.panel.scrollGroupId}
                readOnly={readOnly()}
                onDocChange={handleDocChange}
                onEditorPaste={handleEditorPaste}
                onEditorDrop={handleEditorDrop}
              />
            )}
          </Suspense>
        </DocumentPanelShell>
      </div>
    </MosaicWindow>
  );
}
