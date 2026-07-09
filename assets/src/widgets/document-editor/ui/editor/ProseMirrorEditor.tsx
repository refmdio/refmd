import { createEffect, createMemo, createSignal, onCleanup, Show } from "solid-js";
import { ProsemirrorAdapterProvider, usePluginViewFactory } from "@prosemirror-adapter/solid";
import { EditorView } from "prosemirror-view";
import { EditorState, TextSelection, type Plugin } from "prosemirror-state";
import * as Y from "yjs";
import type { Awareness } from "y-protocols/awareness";
import {
  acquireYDoc,
  emitScrollSync,
  onScrollSync,
  registerEditor,
  releaseYDoc,
  unregisterEditor,
} from "@/features/editor";
import {
  ProseMirrorEditorApi,
  pluginEditorDecorationsPlugin,
} from "../../lib/editor-api/prosemirror-api";
import { MarkdownView, parseMarkdownView } from "@/shared/lib/markdown/markdown-view";
import { markdownSchema } from "../../lib/prosemirror/schema";
import { buildCollabPlugins } from "../../lib/prosemirror/plugin-base";
import { setupCollabPlugins } from "../../lib/prosemirror/plugin-collab";
import { blockHandlePlugin } from "../../lib/prosemirror/plugin-block-handle";
import { placeholderPlugin } from "../../lib/prosemirror/plugin-placeholder";
import { pluginRendererSlotPlugin } from "../../lib/prosemirror/plugin-renderer-slots";
import {
  focusBlankWysiwygEditor,
  syncWysiwygEditorAccessibility,
  WYSIWYG_EDITOR_LABEL,
} from "../../lib/prosemirror/editor-readiness";
import {
  closeSlashCommandMenu,
  executeSlashCommand,
  INACTIVE,
  openSlashCommandMenuBelow,
  slashCommandsPlugin,
} from "../../lib/prosemirror/plugin-slash-commands";
import type { SlashCommand, SlashMenuState } from "../../lib/prosemirror/plugin-slash-commands";
import { readYDocMarkdownPreview } from "../../lib/prosemirror/preview-text";
import { createLocalProseMirrorBridgeDoc } from "../../lib/prosemirror/shared-text-bridge";
import { proseMirrorDocToMarkdown } from "../../lib/prosemirror/markdown-to";
import { SlashMenu } from "./SlashMenu";
import { FloatingToolbar } from "./FloatingToolbar";
import { createSolidBlockHandlePluginView } from "./BlockHandlePluginView";

import "@/shared/lib/markdown/markdown-surface.css";
import "./prosemirror-editor.css";

interface ProseMirrorEditorProps {
  documentId: string;
  stateKey: string;
  panelId: string;
  workspaceId?: string | null;
  scrollGroupId?: string;
  onDocChange?: (change: { persist: boolean }) => void;
  onEditorPaste?: (evt: ClipboardEvent) => void;
  onEditorDrop?: (evt: DragEvent) => void;
  readOnly?: boolean;
}

const PROSEMIRROR_PREVIEW_MAX_CHARS = 64 * 1024;
const REMOTE_CONTENT_READY_EVENT = "refmd:document-remote-content-ready";
const REMOTE_CONTENT_RECONCILE_DELAY_MS = 32;

function normalizeMarkdownText(value: string): string {
  return value.replace(/\r\n?/g, "\n").trim();
}

function expectedRenderedTokens(markdownText: string): string[] {
  let inFence = false;
  return normalizeMarkdownText(markdownText)
    .split("\n")
    .flatMap((line) => {
      const trimmed = line.trim();
      if (trimmed.startsWith("```")) {
        inFence = !inFence;
        return [];
      }

      if (inFence) return [trimmed];

      return [
        trimmed
          .replace(/^#{1,6}\s+/, "")
          .replace(/^[-*+]\s+/, "")
          .replace(/^\d+\.\s+/, "")
          .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
          .replace(/[*_~`]/g, "")
          .trim(),
      ];
    })
    .filter((line) => line.length > 0);
}

function renderedContainsMarkdown(markdownText: string, renderedText: string): boolean {
  const rendered = renderedText.replace(/\s+/g, " ").trim();
  const tokens = expectedRenderedTokens(markdownText);
  return tokens.every((token) => rendered.includes(token.replace(/\s+/g, " ").trim()));
}

function isEditorViewComposing(editorView: EditorView): boolean {
  return (editorView as EditorView & { composing?: boolean }).composing === true;
}

function recordEditorPerf(event: string, detail: Record<string, unknown>): void {
  if (typeof window === "undefined" || !window.__REFMD_E2E__) return;
  const target = window as Window & {
    __refmdE2ESyncPerf?: Array<{
      at: number;
      detail: Record<string, unknown>;
      event: string;
      now: number;
    }>;
  };
  const entry = { event, detail, at: Date.now(), now: performance.now() };
  target.__refmdE2ESyncPerf = target.__refmdE2ESyncPerf ?? [];
  target.__refmdE2ESyncPerf.push(entry);
  window.dispatchEvent(new CustomEvent("refmd:sync-perf", { detail: entry }));
}

export function ProseMirrorEditor(props: ProseMirrorEditorProps) {
  return (
    <ProsemirrorAdapterProvider>
      <ProseMirrorEditorInner {...props} />
    </ProsemirrorAdapterProvider>
  );
}

function ProseMirrorEditorInner(props: ProseMirrorEditorProps) {
  const pluginViewFactory = usePluginViewFactory();
  const createBlockHandleView = createSolidBlockHandlePluginView(pluginViewFactory);
  const scrollSourceId = `pm-${Math.random().toString(36).slice(2)}`;
  const emptyGuideId = `refmd-wysiwyg-empty-guide-${props.panelId}`;
  let containerEl: HTMLDivElement | undefined;
  let view: EditorView | undefined;
  let slashPlugin: Plugin | null = null;
  let undoManager: Y.UndoManager | undefined;
  let activeStateKey: string | undefined;
  let cleanupViewListeners: (() => void) | undefined;
  let destroyCollab: (() => void) | undefined;
  let cleanupYTextRenderRefresh: (() => void) | undefined;
  let cleanupRemoteContentReady: (() => void) | undefined;
  let cleanupLocalBridgeDoc: (() => void) | undefined;
  let unsubScroll: (() => void) | undefined;
  let activeAwareness: Awareness | undefined;
  let previewFrame: number | null = null;
  let renderRefreshFrame: number | null = null;
  let cursorAwarenessFrame: number | null = null;
  let remoteContentReconcileTimer: ReturnType<typeof setTimeout> | null = null;
  let suppressScroll = false;

  const [slashState, setSlashState] = createSignal<SlashMenuState>(INACTIVE);
  const [hasSelection, setHasSelection] = createSignal(false);
  const [selectionVersion, setSelectionVersion] = createSignal(0);
  const [currentView, setCurrentView] = createSignal<EditorView | null>(null);
  const [previewText, setPreviewText] = createSignal("");
  const previewRoot = createMemo(() => parseMarkdownView(previewText()));

  function setInitialPreviewText(yDoc: Y.Doc) {
    const sharedTextLength = yDoc.getText("content").length;
    const text = readYDocMarkdownPreview(yDoc);
    recordEditorPerf("prosemirror_preview_computed", {
      documentId: props.documentId,
      previewTextLength: text.length,
      sharedTextLength,
    });
    setPreviewText(
      text.length > PROSEMIRROR_PREVIEW_MAX_CHARS
        ? text.slice(0, PROSEMIRROR_PREVIEW_MAX_CHARS)
        : text,
    );
  }

  function clearPreviewFrame() {
    if (previewFrame === null) return;
    cancelAnimationFrame(previewFrame);
    previewFrame = null;
  }

  function clearRenderRefreshFrame() {
    if (renderRefreshFrame === null) return;
    cancelAnimationFrame(renderRefreshFrame);
    renderRefreshFrame = null;
  }

  function clearCursorAwarenessFrame() {
    if (cursorAwarenessFrame === null) return;
    cancelAnimationFrame(cursorAwarenessFrame);
    cursorAwarenessFrame = null;
  }

  function clearRemoteContentReconcileTimer() {
    if (remoteContentReconcileTimer === null) return;
    clearTimeout(remoteContentReconcileTimer);
    remoteContentReconcileTimer = null;
  }

  function clearPreviewText(reason: string) {
    if (previewText().trim().length > 0) {
      recordEditorPerf("prosemirror_preview_cleared", {
        documentId: props.documentId,
        reason,
      });
    }
    setPreviewText("");
    clearPreviewFrame();
  }

  function schedulePreviewClear(editorView: EditorView) {
    clearPreviewFrame();
    const startedAt = performance.now();
    const check = () => {
      previewFrame = null;
      if (view !== editorView) return;
      const expectedPreview = previewText().trim();
      const renderedText = (editorView.dom.textContent ?? "").replace(/\s+/g, " ").trim();
      const hasRenderedPreview =
        normalizeMarkdownText(expectedPreview).length === 0 ||
        renderedContainsMarkdown(expectedPreview, renderedText);
      if (hasRenderedPreview || performance.now() - startedAt > 4_000) {
        clearPreviewText(hasRenderedPreview ? "editor-rendered" : "timeout");
        return;
      }
      previewFrame = requestAnimationFrame(check);
    };
    previewFrame = requestAnimationFrame(check);
  }

  function destroyEditor() {
    clearRemoteContentReconcileTimer();
    cleanupRemoteContentReady?.();
    cleanupRemoteContentReady = undefined;
    clearPreviewFrame();
    clearRenderRefreshFrame();
    clearCursorAwarenessFrame();
    cleanupYTextRenderRefresh?.();
    cleanupYTextRenderRefresh = undefined;
    cleanupViewListeners?.();
    cleanupViewListeners = undefined;
    unsubScroll?.();
    unsubScroll = undefined;
    destroyCollab?.();
    destroyCollab = undefined;
    activeAwareness?.setLocalStateField("cursor", null);
    activeAwareness?.setLocalStateField("pmCursor", null);
    activeAwareness = undefined;
    unregisterEditor(props.panelId);
    if (activeStateKey) {
      recordEditorPerf("prosemirror_editor_destroyed", {
        documentId: props.documentId,
        stateKey: activeStateKey,
      });
    }
    view?.destroy();
    view = undefined;
    undoManager?.destroy();
    undoManager = undefined;
    cleanupLocalBridgeDoc?.();
    cleanupLocalBridgeDoc = undefined;
    setCurrentView(null);
    slashPlugin = null;
    if (activeStateKey) {
      releaseYDoc(activeStateKey);
      activeStateKey = undefined;
    }
  }

  function createEditor(stateKey: string) {
    if (!containerEl) return;
    const rootEl = containerEl;

    const { yDoc: sharedYDoc, awareness } = acquireYDoc(stateKey);
    activeStateKey = stateKey;
    activeAwareness = awareness;
    awareness.setLocalStateField("cursor", null);
    setInitialPreviewText(sharedYDoc);
    const localBridgeDoc = createLocalProseMirrorBridgeDoc(sharedYDoc);
    cleanupLocalBridgeDoc = localBridgeDoc.dispose;

    const collab = setupCollabPlugins({
      yDoc: localBridgeDoc.yDoc,
      schema: markdownSchema,
      awareness,
      cursorText: sharedYDoc.getText("content"),
    });

    destroyCollab = collab.destroy;

    const sp = slashCommandsPlugin(markdownSchema);
    slashPlugin = sp;
    let hasFocusedEditorInput = false;
    let hasFocusedLocalDocChange = false;

    const openBlockMenuBelow = (editorView: EditorView, blockPos: number): boolean => {
      editorView.focus();
      recordEditorPerf("prosemirror_block_menu_open", {
        blockPos,
        blockText: editorView.state.doc.nodeAt(blockPos)?.textContent ?? null,
        documentId: props.documentId,
        stateKey,
      });
      return openSlashCommandMenuBelow(editorView, blockPos);
    };

    let destroyed = false;

    const editorPlugins = [
      ...collab.plugins,
      ...(!props.readOnly ? [sp] : []),
      ...buildCollabPlugins(markdownSchema),
      pluginRendererSlotPlugin({
        documentId: props.documentId,
        workspaceId: props.workspaceId,
      }),
      pluginEditorDecorationsPlugin(),
    ];
    if (!props.readOnly) {
      editorPlugins.push(
        placeholderPlugin(),
        blockHandlePlugin({
          createHandleView: createBlockHandleView,
          openBlockMenuBelow,
        }),
      );
    }

    const state = EditorState.create({
      doc: collab.doc,
      plugins: editorPlugins,
    });

    const editorView = new EditorView(containerEl, {
      state,
      attributes: {
        "aria-label": WYSIWYG_EDITOR_LABEL,
        "aria-multiline": "true",
        autocapitalize: "off",
        autocorrect: "off",
        class: "refmd-markdown-surface refmd-editor-readable-surface",
        role: "textbox",
        spellcheck: "false",
      },
      editable: () => !props.readOnly,
      dispatchTransaction(tr) {
        if (destroyed) return;

        const newState = editorView.state.apply(tr);
        editorView.updateState(newState);
        syncWysiwygEditorAccessibility(editorView, {
          emptyGuideId,
          readOnly: props.readOnly,
        });

        if (tr.docChanged) {
          const isYjsSyncChange = collab.bridge.isYjsSyncChange(tr);
          let sharedTextSynced = true;
          if (!isYjsSyncChange) {
            const syncResult = collab.bridge.syncToSharedText(newState.doc);
            sharedTextSynced = syncResult.ok || syncResult.reason === "unchanged";
            if (editorView.hasFocus() && sharedTextSynced) {
              hasFocusedLocalDocChange = true;
            }
            if (!syncResult.ok && syncResult.reason !== "unchanged") {
              recordEditorPerf("prosemirror_shared_text_sync_failed", {
                documentId: props.documentId,
                reason: syncResult.reason,
                stateKey,
              });
            }
          }
          props.onDocChange?.({
            persist: !isYjsSyncChange && sharedTextSynced && editorView.hasFocus(),
          });
        }

        const ss = sp.getState(newState) as SlashMenuState | undefined;
        setSlashState(ss ?? INACTIVE);

        const { from, to } = newState.selection;
        const hasSel = from !== to && editorView.hasFocus();
        setHasSelection(hasSel);
        if (hasSel) setSelectionVersion((v) => v + 1);
      },
    });

    const scheduleCursorAwarenessRefresh = () => {
      clearCursorAwarenessFrame();
      cursorAwarenessFrame = requestAnimationFrame(() => {
        cursorAwarenessFrame = null;
        if (destroyed || view !== editorView || !editorView.hasFocus()) return;
        const currentSlashState = sp.getState(editorView.state) as SlashMenuState | undefined;
        if (currentSlashState?.active) return;
        const selection = editorView.state.selection;
        try {
          editorView.dispatch(
            editorView.state.tr.setSelection(
              TextSelection.create(editorView.state.doc, selection.anchor, selection.head),
            ),
          );
        } catch {
          // Non-text selections do not need Markdown text-cursor awareness refresh.
        }
      });
    };

    view = editorView;
    recordEditorPerf("prosemirror_editor_created", {
      documentId: props.documentId,
      stateKey,
    });
    setCurrentView(editorView);
    syncWysiwygEditorAccessibility(editorView, {
      emptyGuideId,
      readOnly: props.readOnly,
    });
    queueMicrotask(() => {
      if (view === editorView) focusBlankWysiwygEditor(editorView, { readOnly: props.readOnly });
    });
    schedulePreviewClear(editorView);
    const yText = localBridgeDoc.yText;
    const scheduleRenderRefresh = () => {
      clearRenderRefreshFrame();
      renderRefreshFrame = requestAnimationFrame(() => {
        renderRefreshFrame = null;
        if (view !== editorView) return;
        editorView.dom.getBoundingClientRect();
      });
    };
    const yTextRenderObserver = () => scheduleRenderRefresh();
    yText.observe(yTextRenderObserver);
    cleanupYTextRenderRefresh = () => {
      clearRenderRefreshFrame();
      yText.unobserve(yTextRenderObserver);
    };

    const reconcileRemoteContent = () => {
      const editorView = view;
      if (!editorView || activeStateKey !== stateKey) return;
      const expectedText = yText.toJSON();
      const editorText = proseMirrorDocToMarkdown(editorView.state.doc);
      const renderedText = editorView.dom.innerText || editorView.dom.textContent || "";
      const expectedNormalized = normalizeMarkdownText(expectedText);
      const editorNormalized = normalizeMarkdownText(editorText);
      const editorMatches = editorNormalized === expectedNormalized;
      const renderedMatches =
        expectedNormalized.length === 0
          ? normalizeMarkdownText(renderedText).length === 0
          : renderedContainsMarkdown(expectedText, renderedText);
      if (editorMatches && renderedMatches) return;

      scheduleRenderRefresh();
      if (isEditorViewComposing(editorView)) {
        recordEditorPerf("prosemirror_remote_content_reconcile_deferred", {
          documentId: props.documentId,
          editorMatches,
          expectedLength: expectedText.length,
          renderedLength: renderedText.length,
          renderedMatches,
          stateKey,
        });
        return;
      }

      const selection = editorView.state.selection;
      const shouldRestoreFocus = editorView.hasFocus();
      if (
        expectedNormalized.length > 0 &&
        shouldRestoreFocus &&
        (hasFocusedEditorInput || hasFocusedLocalDocChange)
      ) {
        scheduleRenderRefresh();
        recordEditorPerf("prosemirror_remote_content_reconcile_skipped_focused_local_change", {
          documentId: props.documentId,
          editorMatches,
          expectedLength: expectedText.length,
          renderedLength: renderedText.length,
          renderedMatches,
          stateKey,
        });
        return;
      }
      recordEditorPerf(
        shouldRestoreFocus
          ? "prosemirror_remote_content_reconcile_focused_recreate"
          : "prosemirror_remote_content_reconcile_recreate",
        {
          documentId: props.documentId,
          editorMatches,
          expectedLength: expectedText.length,
          renderedLength: renderedText.length,
          renderedMatches,
          stateKey,
        },
      );
      destroyEditor();
      createEditor(stateKey);
      if (view && shouldRestoreFocus) {
        try {
          const docEnd = view.state.doc.content.size;
          const anchor = Math.max(0, Math.min(selection.anchor, docEnd));
          const head = Math.max(0, Math.min(selection.head, docEnd));
          view.dispatch(
            view.state.tr.setSelection(TextSelection.create(view.state.doc, anchor, head)),
          );
        } catch {
          // Restoring focus is more important than exact selection after a stale render refresh.
        }
        view.focus();
      }
    };
    const scheduleRemoteContentReconcile = () => {
      clearRemoteContentReconcileTimer();
      scheduleRenderRefresh();
      queueMicrotask(reconcileRemoteContent);
      remoteContentReconcileTimer = setTimeout(() => {
        remoteContentReconcileTimer = null;
        reconcileRemoteContent();
      }, REMOTE_CONTENT_RECONCILE_DELAY_MS);
    };
    const handleRemoteContentReady = (event: Event) => {
      const detail = (event as CustomEvent<{ stateKey?: string }>).detail;
      if (detail?.stateKey !== stateKey) return;
      scheduleRemoteContentReconcile();
    };
    window.addEventListener(REMOTE_CONTENT_READY_EVENT, handleRemoteContentReady);
    cleanupRemoteContentReady = () => {
      window.removeEventListener(REMOTE_CONTENT_READY_EVENT, handleRemoteContentReady);
    };

    undoManager = new Y.UndoManager(yText);
    registerEditor(props.panelId, new ProseMirrorEditorApi(editorView, yText, undoManager));

    const handlePaste = (event: ClipboardEvent) => props.onEditorPaste?.(event);
    const handleDrop = (event: DragEvent) => props.onEditorDrop?.(event);
    const handleEditorInteraction = () => clearPreviewText("editor-interaction");
    const handleEditorInputIntent = () => {
      hasFocusedEditorInput = true;
      clearPreviewText("editor-interaction");
    };
    const handleCursorAwarenessIntent = () => scheduleCursorAwarenessRefresh();

    editorView.dom.addEventListener("paste", handlePaste);
    editorView.dom.addEventListener("drop", handleDrop);
    editorView.dom.addEventListener("beforeinput", handleEditorInputIntent, true);
    editorView.dom.addEventListener("pointerdown", handleEditorInteraction, true);
    editorView.dom.addEventListener("pointerup", handleCursorAwarenessIntent, true);
    editorView.dom.addEventListener("focusin", handleEditorInteraction, true);
    editorView.dom.addEventListener("focusin", handleCursorAwarenessIntent, true);
    editorView.dom.addEventListener("keydown", handleEditorInputIntent, true);
    editorView.dom.addEventListener("keyup", handleCursorAwarenessIntent, true);

    const groupId = props.scrollGroupId;
    const handleScroll = () => {
      if (suppressScroll || !groupId) return;
      const maxScroll = rootEl.scrollHeight - rootEl.clientHeight;
      if (maxScroll <= 0) return;
      emitScrollSync(groupId, rootEl.scrollTop / maxScroll, scrollSourceId);
    };
    rootEl.addEventListener("scroll", handleScroll, { passive: true });

    if (groupId) {
      unsubScroll = onScrollSync(groupId, (ratio, sourceId) => {
        if (sourceId === scrollSourceId) return;
        const maxScroll = rootEl.scrollHeight - rootEl.clientHeight;
        if (maxScroll <= 0) return;
        suppressScroll = true;
        rootEl.scrollTop = ratio * maxScroll;
        requestAnimationFrame(() => {
          suppressScroll = false;
        });
      });
    }

    cleanupViewListeners = () => {
      destroyed = true;
      editorView.dom.removeEventListener("paste", handlePaste);
      editorView.dom.removeEventListener("drop", handleDrop);
      editorView.dom.removeEventListener("beforeinput", handleEditorInputIntent, true);
      editorView.dom.removeEventListener("pointerdown", handleEditorInteraction, true);
      editorView.dom.removeEventListener("pointerup", handleCursorAwarenessIntent, true);
      editorView.dom.removeEventListener("focusin", handleEditorInteraction, true);
      editorView.dom.removeEventListener("focusin", handleCursorAwarenessIntent, true);
      editorView.dom.removeEventListener("keydown", handleEditorInputIntent, true);
      editorView.dom.removeEventListener("keyup", handleCursorAwarenessIntent, true);
      rootEl.removeEventListener("scroll", handleScroll);
    };
  }

  createEffect(() => {
    const stateKey = props.stateKey;
    if (activeStateKey === stateKey) return;
    destroyEditor();
    createEditor(stateKey);
  });

  createEffect(() => {
    const readOnly = props.readOnly;
    if (view) {
      view.setProps({ editable: () => !readOnly });
      syncWysiwygEditorAccessibility(view, { emptyGuideId, readOnly });
    }
  });

  onCleanup(destroyEditor);

  function handleSlashSelect(cmd: SlashCommand) {
    if (!view || !slashPlugin) return;

    const ss = slashPlugin.getState(view.state) as SlashMenuState | undefined;
    if (!ss?.active) return;
    recordEditorPerf("prosemirror_slash_select", {
      documentId: props.documentId,
      insertAfterBlockPos: ss.insertAfterBlockPos ?? null,
      insertAfterBlockText:
        typeof ss.insertAfterBlockPos === "number"
          ? (view.state.doc.nodeAt(ss.insertAfterBlockPos)?.textContent ?? null)
          : null,
      mode: ss.mode,
      stateKey: props.stateKey,
    });

    const nextState = {
      ...ss,
      commands: [cmd],
      selectedIndex: 0,
    } satisfies SlashMenuState;
    executeSlashCommand(view, nextState);
  }

  function handleSlashDismiss() {
    if (!view) return;
    closeSlashCommandMenu(view);
  }

  return (
    <>
      <div class="relative h-full">
        <span id={emptyGuideId} class="sr-only">
          Start writing, or type / for blocks.
        </span>
        <div
          ref={(el) => {
            containerEl = el;
            createEditor(props.stateKey);
          }}
          class="h-full overflow-auto relative"
        />
        <Show when={previewText().trim().length > 0}>
          <div
            class="pointer-events-none absolute inset-0 overflow-auto bg-background text-foreground"
            data-refmd-content-preview="true"
          >
            <div class="refmd-editor-readable-surface py-4 pl-[4rem] pr-[3.25rem] text-foreground">
              <MarkdownView root={previewRoot()} />
            </div>
          </div>
        </Show>
      </div>
      <Show when={!props.readOnly && currentView() && slashState().active}>
        <SlashMenu
          view={currentView()!}
          slashState={slashState()}
          onDismiss={handleSlashDismiss}
          onSelect={handleSlashSelect}
        />
      </Show>
      <Show when={!props.readOnly && currentView() && hasSelection()}>
        <FloatingToolbar
          view={currentView()!}
          schema={markdownSchema}
          selectionVersion={selectionVersion()}
        />
      </Show>
    </>
  );
}
