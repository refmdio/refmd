import { For, Show, Suspense, createEffect, createSignal, lazy, on, onCleanup } from "solid-js";
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
  type EditorLike,
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
import {
  workspaceTileCanOpenFromDocumentMenu,
  type WorkspaceTileConfig,
} from "@/shared/lib/workspace/app";
import { DocumentTileShell } from "./DocumentTileShell";
import { DocumentTilePhaseContent } from "./DocumentTilePhaseContent";
import {
  getDefaultPluginUiContributionRegistry,
  pluginUiCommandId,
  pluginUiCommandResourcePayload,
  pluginUiEntryCommandEnabled,
  type PluginUiResourceContext,
  type PluginUiRegistryEntry,
} from "@/features/plugin-runtime";
import {
  createPluginEditorHandle,
  getDefaultPluginEditorContributionRegistry,
  getDefaultPluginEditorPlaintextStore,
  invokePluginEditorCommand,
  pluginEditorDecorationsWithinContext,
  issuePluginEditorPlaintext,
  pluginEditorDiagnosticsWithinContext,
  pluginEditorDecorationSourceId,
  pluginEditorSuggestionsWithinContext,
  pluginEditorTextEditsWithinContext,
  requestPluginDecoration,
  requestPluginDiagnostics,
  requestPluginFormatter,
  requestPluginSuggestion,
  type PluginDecorationItem,
  type PluginDiagnosticItem,
  type PluginEditorContributionEntry,
  type PluginSuggestionItem,
} from "@/features/plugin-runtime";
import {
  createWorkspaceTilePluginResourceContext,
  pluginEditorContributionMatchesWorkspace,
  pluginUiEntryResourceContext,
} from "./plugin-extension-context";
import { readInitializedDocumentPreviewText } from "./document-preview";

type Workspace = ReturnType<typeof usePanelWorkspace>;
type EditorPlaintextContext = {
  kind: "selection" | "context";
  range: { anchor: number; head: number };
  plaintext: string;
  maxBytes: number;
};

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

const EDITOR_FALLBACK_PREVIEW_MAX_CHARS = 64 * 1024;
const SHARE_CONTENT_VISIBLE_EVENT = "refmd:share-content-visible";

function truncateEditorFallbackPreviewText(text: string): string {
  return text.length > EDITOR_FALLBACK_PREVIEW_MAX_CHARS
    ? text.slice(0, EDITOR_FALLBACK_PREVIEW_MAX_CHARS)
    : text;
}

function notifyShareContentVisible(detail: Record<string, unknown>): void {
  if (typeof window === "undefined" || !window.location.pathname.startsWith("/share/")) return;
  window.dispatchEvent(new CustomEvent(SHARE_CONTENT_VISIBLE_EVENT, { detail }));
}

function EditorFallback(props: { stateKey: string }) {
  const [previewText, setPreviewText] = createSignal("");
  let previewRefreshTimer: ReturnType<typeof setInterval> | null = null;

  const clearPreviewRefreshTimer = () => {
    if (previewRefreshTimer === null) return;
    clearInterval(previewRefreshTimer);
    previewRefreshTimer = null;
  };
  const applyPreviewText = (text: string) => {
    const next = truncateEditorFallbackPreviewText(text);
    setPreviewText(next);
    if (next.trim().length > 0) {
      notifyShareContentVisible({
        source: "editor-fallback",
        stateKey: props.stateKey,
        previewTextLength: next.length,
      });
      clearPreviewRefreshTimer();
    }
  };
  const refreshPreviewText = () => {
    const next = readInitializedDocumentPreviewText(props.stateKey);
    if (next.text.trim().length > 0) {
      applyPreviewText(next.text);
      return;
    }
    if (next.initialized) clearPreviewRefreshTimer();
  };

  createEffect(() => {
    refreshPreviewText();
    if (typeof window === "undefined" || previewRefreshTimer !== null) return;
    previewRefreshTimer = window.setInterval(refreshPreviewText, 50);
  });
  onCleanup(clearPreviewRefreshTimer);

  const visiblePreviewText = () => (previewText().trim().length > 0 ? previewText() : "");

  return (
    <Show
      when={visiblePreviewText()}
      fallback={
        <div class="flex h-full items-center justify-center bg-background">
          <DocumentTilePhaseContent
            label="Mounting editor DOM"
            detail="Preparing plugin contributions and editor surface."
            value={72}
          />
        </div>
      }
    >
      <div
        class="h-full overflow-auto bg-background px-6 py-5 whitespace-pre-wrap break-words text-sm leading-6 text-foreground"
        data-refmd-content-preview="true"
      >
        {previewText()}
      </div>
    </Show>
  );
}

export function DocumentTile(props: DocumentTileProps) {
  const [registryVersion, setRegistryVersion] = createSignal(0);
  const [editorContributionVersion, setEditorContributionVersion] = createSignal(0);
  const [editorContextMenu, setEditorContextMenu] = createSignal<{ x: number; y: number } | null>(
    null,
  );
  const [editorContextMenuSelection, setEditorContextMenuSelection] =
    createSignal<EditorPlaintextContext | null>(null);
  const [pluginDiagnostics, setPluginDiagnostics] = createSignal<PluginDiagnosticItem[]>([]);
  const [pluginSuggestions, setPluginSuggestions] = createSignal<PluginSuggestionItem[]>([]);
  const uiRegistry = getDefaultPluginUiContributionRegistry();
  const editorContributionRegistry = getDefaultPluginEditorContributionRegistry();
  const pluginDecorationSources = new Set<string>();
  const unsubscribeRegistry = uiRegistry.subscribe(() => setRegistryVersion((value) => value + 1));
  const unsubscribeEditorContributions = editorContributionRegistry.subscribe(() =>
    setEditorContributionVersion((value) => value + 1),
  );
  const unsubscribeEditorDecorationCleanup = editorContributionRegistry.subscribeDecorationCleanup(
    (sourceIds) =>
      clearPluginEditorDecorationSources(props.panelId, pluginDecorationSources, sourceIds),
  );
  const documentEvents = getDocumentEvents();
  let syncLimitNoticeRelease: (() => void) | null = null;
  let syncLimitNoticeId: string | null = null;
  let editorProviderRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  let editorProviderRefreshGeneration = 0;
  const maxEditorProviderRefreshAttempts = 40;
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
  const clearEditorProviderRefresh = () => {
    if (editorProviderRefreshTimer === null) return;
    clearTimeout(editorProviderRefreshTimer);
    editorProviderRefreshTimer = null;
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

  const closeEditorContextMenu = () => {
    setEditorContextMenu(null);
    setEditorContextMenuSelection(null);
  };
  const handleGlobalPointerDown = () => closeEditorContextMenu();
  const handleGlobalKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") closeEditorContextMenu();
  };
  if (typeof window !== "undefined") {
    window.addEventListener("pointerdown", handleGlobalPointerDown);
    window.addEventListener("keydown", handleGlobalKeyDown);
  }

  onCleanup(() => {
    if (typeof window !== "undefined") {
      window.removeEventListener("pointerdown", handleGlobalPointerDown);
      window.removeEventListener("keydown", handleGlobalKeyDown);
    }
    unsubscribeRegistry();
    unsubscribeEditorContributions();
    unsubscribeEditorDecorationCleanup();
    clearEditorProviderRefresh();
    editorProviderRefreshGeneration += 1;
    clearSyncLimitNotice();
    clearPluginEditorDecorations(props.panelId, pluginDecorationSources);
  });
  const pluginTabMenuItems = () => {
    registryVersion();
    return uiRegistry
      .list("menu_item")
      .filter(
        (entry) =>
          entry.contribution.surface === "menu_item" &&
          entry.contribution.placement === "document_tab_menu" &&
          ((context) => context && pluginUiEntryCommandEnabled(entry, context, uiRegistry))(
            resourceContext(entry),
          ),
      );
  };
  const pluginWorkspaceTiles = () => {
    registryVersion();
    const context = workspaceTileResourceContext();
    if (!context) return [];
    return workspaceManager
      .getWorkspaceTiles()
      .filter(
        (tile) =>
          workspaceTileCanOpenFromDocumentMenu(tile) && (tile.isAvailable?.(context) ?? false),
      );
  };
  const pluginEditorMenuItems = () => {
    registryVersion();
    return uiRegistry
      .list("menu_item")
      .filter(
        (entry) =>
          entry.contribution.surface === "menu_item" &&
          entry.contribution.placement === "editor_context_menu" &&
          ((context) => context && pluginUiEntryCommandEnabled(entry, context, uiRegistry))(
            resourceContext(entry),
          ),
      );
  };
  const pluginEditorContributions = () => {
    editorContributionVersion();
    return editorContributionRegistry
      .listEntries()
      .filter(
        (entry) =>
          entry.session &&
          pluginEditorContributionMatchesWorkspace(entry, props.workspaceId) &&
          [
            "command",
            "editor_command",
            "formatter",
            "decoration",
            "diagnostics",
            "suggestion",
          ].includes(entry.descriptor.kind),
      );
  };
  const pluginEditorProviderContributions = () =>
    pluginEditorContributions().filter((entry) =>
      ["decoration", "diagnostics", "suggestion"].includes(entry.descriptor.kind),
    );
  const showPluginProviderPanel = () =>
    props.workspace.focusedPanelId() === props.panelId &&
    (pluginDiagnostics().length > 0 || pluginSuggestions().length > 0);
  const queuePluginEditorProviderRefresh = (
    generation: number,
    delayMs: number,
    attempt: number,
  ) => {
    clearEditorProviderRefresh();
    editorProviderRefreshTimer = setTimeout(() => {
      editorProviderRefreshTimer = null;
      void refreshPluginEditorProviders(generation, attempt);
    }, delayMs);
  };
  const schedulePluginEditorProviderRefresh = () => {
    const generation = ++editorProviderRefreshGeneration;
    queuePluginEditorProviderRefresh(generation, 250, 0);
  };
  const refreshPluginEditorProviders = async (generation: number, attempt: number) => {
    const entries = pluginEditorProviderContributions();
    if (entries.length === 0) {
      clearPluginEditorProviderState({
        panelId: props.panelId,
        decorationSources: pluginDecorationSources,
        setDiagnostics: setPluginDiagnostics,
        setSuggestions: setPluginSuggestions,
      });
      return;
    }
    const editor = getEditor(props.panelId);
    if (!editor) {
      if (
        generation === editorProviderRefreshGeneration &&
        attempt < maxEditorProviderRefreshAttempts
      ) {
        queuePluginEditorProviderRefresh(generation, 250, attempt + 1);
      }
      return;
    }

    for (const entry of entries) {
      if (generation !== editorProviderRefreshGeneration) return;
      try {
        await runPluginEditorContribution(entry, {
          panelId: props.panelId,
          documentId: props.panel.documentId,
          onDiagnostics(items) {
            if (generation === editorProviderRefreshGeneration) setPluginDiagnostics(items);
          },
          onDecorations(sourceId, items) {
            if (generation !== editorProviderRefreshGeneration) return;
            const activeEditor = getEditor(props.panelId);
            if (!activeEditor) return;
            pluginDecorationSources.add(sourceId);
            activeEditor.setPluginDecorations(sourceId, items);
          },
          onSuggestions(items) {
            if (generation === editorProviderRefreshGeneration) setPluginSuggestions(items);
          },
        });
      } catch {
        if (entry.descriptor.kind === "diagnostics") setPluginDiagnostics([]);
        if (entry.descriptor.kind === "suggestion") setPluginSuggestions([]);
        if (entry.descriptor.kind === "decoration") {
          clearPluginEditorDecorationSources(props.panelId, pluginDecorationSources, [
            pluginEditorDecorationSourceId(entry),
          ]);
        }
      }
    }
  };
  createEffect(
    on(
      () => [props.panel.documentId, props.panel.type] as const,
      () => {
        clearPluginEditorDecorations(props.panelId, pluginDecorationSources);
        setPluginDiagnostics([]);
        setPluginSuggestions([]);
        schedulePluginEditorProviderRefresh();
      },
    ),
  );

  createEffect(
    on(
      () =>
        [
          props.panel.documentId,
          props.panel.type,
          pluginEditorProviderContributions()
            .map(
              (entry) =>
                `${entry.owner.activationId}:${entry.descriptor.kind}:${entry.descriptor.id}`,
            )
            .join("|"),
        ] as const,
      () => schedulePluginEditorProviderRefresh(),
    ),
  );
  const resourceContext = (entry: PluginUiRegistryEntry): PluginUiResourceContext | null =>
    pluginUiEntryResourceContext(entry, {
      workspaceId: props.workspaceId,
      documentId: props.panel.documentId,
      selectionPresent: !!getEditor(props.panelId)?.somethingSelected(),
    });
  const workspaceTileResourceContext = () =>
    createWorkspaceTilePluginResourceContext({
      workspaceId: props.workspaceId,
      documentId: props.panel.documentId,
      selectionPresent: !!getEditor(props.panelId)?.somethingSelected(),
    });
  const openPluginWorkspaceTile = async (panel: WorkspaceTileConfig) => {
    const context = workspaceTileResourceContext();
    if (!context) return;
    const allowed = await panel.open?.(context);
    if (allowed === false) return;
    props.workspace.openWorkspaceTile(panel.id, props.panel.documentId);
  };
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
  const handleDocChange = (change?: { persist?: boolean }) => {
    const { editor, documentView } = getDocumentEventContext();
    if (change?.persist !== false) {
      const state = getDocumentState(props.panel.targetKey);
      if (state?.autoSync) {
        state.autoSync.notifyLocalEdit();
      } else if (state && !state.readOnly) {
        state._preAutoSyncUserEdit = true;
      }
    }
    clearPluginEditorDecorations(props.panelId, pluginDecorationSources);
    schedulePluginEditorProviderRefresh();
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
              <For each={pluginTabMenuItems()}>
                {(entry) => (
                  <DropdownMenuItem
                    onClick={() => {
                      const context = resourceContext(entry);
                      if (context) runPluginMenuCommand(entry, context, uiRegistry);
                    }}
                  >
                    {pluginMenuTitle(entry)}
                  </DropdownMenuItem>
                )}
              </For>
              <For each={pluginWorkspaceTiles()}>
                {(panel) => (
                  <DropdownMenuItem
                    onClick={() => {
                      void openPluginWorkspaceTile(panel);
                    }}
                  >
                    {panel.title}
                  </DropdownMenuItem>
                )}
              </For>
              <Show when={pluginTabMenuItems().length > 0 || pluginWorkspaceTiles().length > 0}>
                <DropdownMenuSeparator />
              </Show>
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
        class="relative h-full"
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
        onContextMenu={(event) => {
          const editor = getEditor(props.panelId);
          const selectionContext = editor ? editorPlaintextContext(editor, "selection") : null;
          if (editor) {
            workspaceManager.trigger("editor-menu", null, editor, {
              id: props.panel.documentId,
              title: props.title,
              editor,
            });
          }
          if (pluginEditorMenuItems().length > 0 || pluginEditorContributions().length > 0) {
            event.preventDefault();
            setEditorContextMenuSelection(selectionContext);
            setEditorContextMenu({ x: event.clientX, y: event.clientY });
          }
        }}
      >
        <DocumentTileShell
          documentId={props.panel.documentId}
          showDialogs={props.workspace.focusedPanelId() === props.panelId}
          stateKey={props.panel.targetKey}
          workspaceId={props.workspaceId}
        >
          <Suspense fallback={<EditorFallback stateKey={props.panel.targetKey} />}>
            {isMarkdown() ? (
              <CodeMirrorEditorImpl
                documentId={props.panel.documentId}
                stateKey={props.panel.targetKey}
                panelId={props.panelId}
                workspaceId={props.workspaceId}
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
                workspaceId={props.workspaceId}
                scrollGroupId={props.panel.scrollGroupId}
                readOnly={readOnly()}
                onDocChange={handleDocChange}
                onEditorPaste={handleEditorPaste}
                onEditorDrop={handleEditorDrop}
              />
            )}
          </Suspense>
        </DocumentTileShell>
        <Show
          when={
            editorContextMenu() &&
            (pluginEditorMenuItems().length > 0 || pluginEditorContributions().length > 0)
          }
        >
          <div
            class="fixed z-50 min-w-40 rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-md"
            style={{
              left: `${editorContextMenu()?.x ?? 0}px`,
              top: `${editorContextMenu()?.y ?? 0}px`,
            }}
            onPointerDown={(event) => event.stopPropagation()}
          >
            <For each={pluginEditorMenuItems()}>
              {(entry) => (
                <button
                  type="button"
                  class="flex w-full items-center rounded px-2 py-1.5 text-left text-xs hover:bg-accent hover:text-accent-foreground"
                  onClick={() => {
                    const context = resourceContext(entry);
                    if (context) runPluginMenuCommand(entry, context, uiRegistry);
                    closeEditorContextMenu();
                  }}
                >
                  {pluginMenuTitle(entry)}
                </button>
              )}
            </For>
            <For each={pluginEditorContributions()}>
              {(entry) => (
                <button
                  type="button"
                  class="flex w-full items-center rounded px-2 py-1.5 text-left text-xs hover:bg-accent hover:text-accent-foreground"
                  onClick={() => {
                    const selectionContext = editorContextMenuSelection();
                    void runPluginEditorContribution(entry, {
                      panelId: props.panelId,
                      documentId: props.panel.documentId,
                      selectionContext,
                      onDiagnostics: setPluginDiagnostics,
                      onDecorations(sourceId, items) {
                        const editor = getEditor(props.panelId);
                        if (!editor) return;
                        pluginDecorationSources.add(sourceId);
                        editor.setPluginDecorations(sourceId, items);
                      },
                      onSuggestions: setPluginSuggestions,
                    });
                    closeEditorContextMenu();
                  }}
                >
                  {entry.descriptor.title}
                </button>
              )}
            </For>
          </div>
        </Show>
        <Show when={showPluginProviderPanel()}>
          <div class="absolute bottom-3 right-3 z-40 max-w-sm rounded-md border border-border bg-popover p-2 text-xs text-popover-foreground shadow-md">
            <For each={pluginDiagnostics()}>
              {(item) => (
                <div class="mb-1">
                  <span class="font-medium">{item.severity}</span>
                  <span class="ml-1">{item.message}</span>
                </div>
              )}
            </For>
            <For each={pluginSuggestions()}>
              {(item) => (
                <button
                  type="button"
                  class="block w-full rounded px-2 py-1 text-left hover:bg-accent hover:text-accent-foreground"
                  onClick={() => {
                    applyPluginSuggestion(props.panelId, item);
                    setPluginSuggestions((items) =>
                      items.filter((candidate) => candidate.id !== item.id),
                    );
                  }}
                >
                  {item.label}
                </button>
              )}
            </For>
          </div>
        </Show>
      </div>
    </MosaicWindow>
  );
}

function pluginMenuTitle(entry: PluginUiRegistryEntry): string {
  const contribution = entry.contribution;
  return contribution.surface === "menu_item" ? contribution.title : "";
}

function runPluginMenuCommand(
  entry: PluginUiRegistryEntry,
  context: PluginUiResourceContext,
  registry: ReturnType<typeof getDefaultPluginUiContributionRegistry>,
): void {
  const contribution = entry.contribution;
  if (contribution.surface !== "menu_item") return;
  const payload = pluginUiCommandResourcePayload(entry, context, registry);
  if (!payload) return;
  const commandId = pluginUiCommandId(entry, contribution.command_ref);
  workspaceManager
    .listCommands()
    .find((command) => command.id === commandId)
    ?.callback?.(payload);
}

async function runPluginEditorContribution(
  entry: PluginEditorContributionEntry,
  options: {
    panelId: string;
    documentId: string;
    selectionContext?: EditorPlaintextContext | null;
    onDiagnostics(items: PluginDiagnosticItem[]): void;
    onDecorations(sourceId: string, items: PluginDecorationItem[]): void;
    onSuggestions(items: PluginSuggestionItem[]): void;
  },
): Promise<void> {
  const session = entry.session;
  const editor = getEditor(options.panelId);
  if (!session || !editor) return;

  const handle = createPluginEditorHandle(options.panelId, options.documentId);
  if (entry.descriptor.kind === "command" || entry.descriptor.kind === "editor_command") {
    await invokePluginEditorCommand(session, entry.descriptor, handle, {
      document_id: options.documentId,
    });
    return;
  }

  const plaintextKind =
    entry.descriptor.kind === "formatter"
      ? entry.descriptor.input === "selection"
        ? "selection"
        : "context"
      : "context";
  const context =
    plaintextKind === "selection"
      ? options.selectionContext?.kind === "selection"
        ? options.selectionContext
        : editorPlaintextContext(editor, "selection")
      : editorPlaintextContext(editor, "context");
  if (!context) return;
  const plaintextHandle = issuePluginEditorPlaintext({
    session,
    store: getDefaultPluginEditorPlaintextStore(),
    editor: handle,
    plaintextKind: context.kind,
    invocationKind:
      entry.descriptor.kind === "suggestion"
        ? "editor_suggestion"
        : entry.descriptor.kind === "decoration"
          ? "editor_decoration"
          : entry.descriptor.kind === "formatter"
            ? "formatter"
            : "editor_suggestion",
    hostInvocation:
      entry.descriptor.kind === "suggestion"
        ? { kind: "editor_suggestion_provider", userGesture: false }
        : entry.descriptor.kind === "decoration"
          ? { kind: "editor_decoration_provider", userGesture: false }
          : entry.descriptor.kind === "formatter"
            ? { kind: "formatter", userGesture: true }
            : { kind: "editor_suggestion_provider", userGesture: false },
    range: context.range,
    plaintext: context.plaintext,
    maxBytes: context.maxBytes,
  });

  try {
    if (entry.descriptor.kind === "formatter") {
      const result = await requestPluginFormatter(session, entry.descriptor, plaintextHandle);
      if (pluginEditorTextEditsWithinContext(result.edits, context.range)) {
        applyPluginTextEdits(editor, result.edits);
      }
    } else if (entry.descriptor.kind === "diagnostics") {
      const result = await requestPluginDiagnostics(session, entry.descriptor, plaintextHandle);
      options.onDiagnostics(
        pluginEditorDiagnosticsWithinContext(result.diagnostics, context.range)
          ? result.diagnostics
          : [],
      );
    } else if (entry.descriptor.kind === "decoration") {
      const sourceId = pluginEditorDecorationSourceId(entry);
      const result = await requestPluginDecoration(session, entry.descriptor, plaintextHandle);
      options.onDecorations(
        sourceId,
        pluginEditorDecorationsWithinContext(result.decorations, context.range)
          ? result.decorations
          : [],
      );
    } else if (entry.descriptor.kind === "suggestion") {
      const result = await requestPluginSuggestion(session, entry.descriptor, plaintextHandle);
      options.onSuggestions(
        pluginEditorSuggestionsWithinContext(result.suggestions, context.range)
          ? result.suggestions
          : [],
      );
    }
  } finally {
    plaintextHandle.dispose();
  }
}

function clearPluginEditorDecorations(panelId: string, sources: Set<string>): void {
  const editor = getEditor(panelId);
  if (editor) {
    for (const sourceId of sources) editor.clearPluginDecorations(sourceId);
  }
  sources.clear();
}

export function clearPluginEditorProviderState(options: {
  panelId: string;
  decorationSources: Set<string>;
  setDiagnostics(items: PluginDiagnosticItem[]): void;
  setSuggestions(items: PluginSuggestionItem[]): void;
}): void {
  clearPluginEditorDecorations(options.panelId, options.decorationSources);
  options.setDiagnostics([]);
  options.setSuggestions([]);
}

function clearPluginEditorDecorationSources(
  panelId: string,
  trackedSources: Set<string>,
  sourceIds: readonly string[],
): void {
  const editor = getEditor(panelId);
  for (const sourceId of sourceIds) {
    if (!trackedSources.delete(sourceId)) continue;
    editor?.clearPluginDecorations(sourceId);
  }
}

function editorPlaintextContext(
  editor: EditorLike,
  kind: "selection" | "context",
): EditorPlaintextContext | null {
  const value = editor.getValue();
  const maxBytes = 16 * 1024;
  if (kind === "selection") {
    if (!editor.somethingSelected()) return null;
    const from = editor.posToOffset(editor.getCursor("from"));
    const to = editor.posToOffset(editor.getCursor("to"));
    return {
      kind: "selection" as const,
      range: { anchor: from, head: to },
      plaintext: editor.getSelection().slice(0, maxBytes),
      maxBytes,
    };
  }

  const cursor = editor.posToOffset(editor.getCursor("head"));
  const from = Math.max(0, cursor - maxBytes / 2);
  const to = Math.min(value.length, from + maxBytes);
  return {
    kind: "context" as const,
    range: { anchor: from, head: to },
    plaintext: value.slice(from, to),
    maxBytes,
  };
}

function applyPluginTextEdits(
  editor: EditorLike,
  edits: { range: { from: number; to: number }; text: string }[],
): void {
  const nextValue = applyPluginTextEditsToValue(editor.getValue(), edits);
  if (nextValue === null) return;
  editor.setValue(nextValue);
}

function applyPluginTextEditsToValue(
  value: string,
  edits: { range: { from: number; to: number }; text: string }[],
): string | null {
  let nextValue = value;
  const ordered = [...edits].sort((a, b) => b.range.from - a.range.from);
  for (const edit of ordered) {
    if (
      edit.range.from < 0 ||
      edit.range.to < edit.range.from ||
      edit.range.to > nextValue.length
    ) {
      return null;
    }
    nextValue = nextValue.slice(0, edit.range.from) + edit.text + nextValue.slice(edit.range.to);
  }
  return nextValue;
}

function applyPluginSuggestion(panelId: string, item: PluginSuggestionItem): void {
  const editor = getEditor(panelId);
  if (!editor) return;
  if (item.range) {
    editor.replaceRange(
      item.insert_text,
      editor.offsetToPos(item.range.from),
      editor.offsetToPos(item.range.to),
    );
  } else {
    editor.replaceSelection(item.insert_text);
  }
}
