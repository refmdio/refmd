import { createEffect, onCleanup } from "solid-js";
import { EditorState, Compartment, type Extension } from "@codemirror/state";
import {
  EditorView,
  ViewPlugin,
  drawSelection,
  dropCursor,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  keymap,
  lineNumbers,
} from "@codemirror/view";
import { defaultKeymap } from "@codemirror/commands";
import type { ViewUpdate } from "@codemirror/view";
import { markdown } from "@codemirror/lang-markdown";
import {
  HighlightStyle,
  bracketMatching,
  indentOnInput,
  syntaxHighlighting,
} from "@codemirror/language";
import { tags } from "@lezer/highlight";
import { yCollab, ySyncFacet, yUndoManagerKeymap } from "y-codemirror.next";
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
import { EditorApi, pluginEditorDecorationsExtension } from "../../lib/editor-api/codemirror-api";
import { pluginRendererSlotExtension } from "../../lib/codemirror/plugin-renderer-slots";
import { ensureYDocMarkdownText } from "../../lib/prosemirror/preview-text";
import "./codemirror-cursors.css";

function createEditorTheme(dark: boolean) {
  return EditorView.theme(
    {
      "&": {
        height: "100%",
        fontSize: "14px",
        backgroundColor: "var(--background)",
        color: "var(--foreground)",
      },
      ".cm-scroller": {
        overflow: "auto",
        fontFamily: "var(--font-mono)",
      },
      ".cm-content": {
        boxSizing: "border-box",
        minWidth: "0",
        padding: "1rem",
        caretColor: "var(--foreground)",
      },
      ".cm-line": {
        overflowWrap: "anywhere",
      },
      ".cm-cursor": {
        borderLeftColor: "var(--foreground)",
      },
      ".cm-activeLine": {
        backgroundColor: "var(--muted)",
      },
      ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": {
        backgroundColor: "var(--selection-background)",
      },
      ".cm-content::selection, .cm-content *::selection": {
        backgroundColor: "var(--selection-background)",
        color: "var(--foreground)",
      },
      ".cm-gutters": {
        backgroundColor: "var(--background)",
        color: "var(--muted-foreground)",
        border: "none",
      },
      ".cm-activeLineGutter": {
        backgroundColor: "var(--muted)",
      },
      ".cm-lineNumbers .cm-gutterElement": {
        color: "var(--muted-foreground)",
      },
      ".refmd-plugin-editor-decoration-highlight": {
        backgroundColor: "color-mix(in srgb, var(--accent) 28%, transparent)",
      },
      ".refmd-plugin-editor-decoration-underline": {
        textDecoration: "underline",
        textDecorationThickness: "2px",
        textUnderlineOffset: "2px",
      },
      ".refmd-plugin-editor-decoration-gutter_marker": {
        boxShadow: "inset 2px 0 0 var(--accent)",
      },
      ".refmd-plugin-editor-decoration-info": {
        outlineColor: "color-mix(in srgb, var(--accent) 72%, transparent)",
      },
      ".refmd-plugin-editor-decoration-warning": {
        backgroundColor: "color-mix(in srgb, #f59e0b 24%, transparent)",
        textDecorationColor: "#d97706",
      },
    },
    { dark },
  );
}

function createHighlighting() {
  return HighlightStyle.define([
    { tag: tags.heading1, fontWeight: "bold", fontSize: "1.5em" },
    { tag: tags.heading2, fontWeight: "bold", fontSize: "1.3em" },
    { tag: tags.heading3, fontWeight: "bold", fontSize: "1.1em" },
    { tag: tags.heading, fontWeight: "bold" },
    { tag: tags.emphasis, fontStyle: "italic" },
    { tag: tags.strong, fontWeight: "bold" },
    { tag: tags.link, color: "var(--primary)", textDecoration: "underline" },
    { tag: tags.url, color: "var(--primary)" },
    {
      tag: tags.monospace,
      fontFamily: "var(--font-mono)",
      backgroundColor: "var(--muted)",
    },
    { tag: tags.quote, color: "var(--muted-foreground)", fontStyle: "italic" },
    { tag: tags.strikethrough, textDecoration: "line-through" },
    { tag: tags.processingInstruction, color: "var(--muted-foreground)" },
  ]);
}

const lightTheme = createEditorTheme(false);
const darkTheme = createEditorTheme(true);
const markdownHighlighting = createHighlighting();
const REMOTE_CONTENT_READY_EVENT = "refmd:document-remote-content-ready";
const REMOTE_CONTENT_RECONCILE_DELAY_MS = 32;
const REMOTE_CURSOR_LABEL_RE =
  /\u2060+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\u2060*/gi;

function recordEditorPerf(event: string, detail: Record<string, unknown>): void {
  if (typeof window === "undefined" || !window.__REFMD_E2E__) return;
  const payload = {
    event,
    detail,
    at: Date.now(),
    now: performance.now(),
  };
  const target = window as Window & { __refmdE2ESyncPerf?: unknown[] };
  target.__refmdE2ESyncPerf ??= [];
  target.__refmdE2ESyncPerf.push(payload);
  window.dispatchEvent(new CustomEvent("refmd:sync-perf", { detail: payload }));
}

function normalizeRenderedText(value: string): string {
  return value.replace(REMOTE_CURSOR_LABEL_RE, "");
}

function readRenderedCodeMirrorText(editorView: EditorView): string {
  const lines = [...editorView.contentDOM.querySelectorAll<HTMLElement>(".cm-line")].map((line) =>
    normalizeRenderedText(line.textContent ?? ""),
  );
  if (lines.length > 0) return lines.join("\n");
  return normalizeRenderedText(editorView.contentDOM.textContent ?? "");
}

function isDarkMode(): boolean {
  return document.documentElement.classList.contains("dark");
}

function createBaseExtensions(): Extension[] {
  return [
    lineNumbers(),
    highlightActiveLineGutter(),
    highlightSpecialChars(),
    EditorView.lineWrapping,
    drawSelection(),
    dropCursor(),
    EditorState.allowMultipleSelections.of(true),
    indentOnInput(),
    bracketMatching(),
    highlightActiveLine(),
    pluginEditorDecorationsExtension,
    keymap.of([...yUndoManagerKeymap, ...defaultKeymap]),
  ];
}

interface CodeMirrorEditorProps {
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

export function CodeMirrorEditor(props: CodeMirrorEditorProps) {
  const themeCompartment = new Compartment();
  const editableCompartment = new Compartment();
  const keymapCompartment = new Compartment();
  const scrollSourceId = `cm-${Math.random().toString(36).slice(2)}`;
  let containerEl: HTMLDivElement | undefined;
  let view: EditorView | undefined;
  let undoManager: Y.UndoManager | undefined;
  let themeObserver: MutationObserver | undefined;
  let activeStateKey: string | undefined;
  let activeAwareness: Awareness | undefined;
  let unsubScroll: (() => void) | undefined;
  let cleanupContainerFocus: (() => void) | undefined;
  let cleanupYTextRenderRefresh: (() => void) | undefined;
  let cleanupRemoteContentReady: (() => void) | undefined;
  let remoteContentReconcileTimer: ReturnType<typeof setTimeout> | null = null;
  let suppressScroll = false;
  let lastPointerFocusRequestAt = 0;

  function clearRemoteContentReconcileTimer() {
    if (remoteContentReconcileTimer === null) return;
    clearTimeout(remoteContentReconcileTimer);
    remoteContentReconcileTimer = null;
  }

  function destroyEditor() {
    const editorView = view;
    const syncUndoManager = editorView?.state.facet(ySyncFacet).undoManager;
    clearRemoteContentReconcileTimer();
    cleanupRemoteContentReady?.();
    cleanupRemoteContentReady = undefined;
    cleanupYTextRenderRefresh?.();
    cleanupYTextRenderRefresh = undefined;
    cleanupContainerFocus?.();
    cleanupContainerFocus = undefined;
    unsubScroll?.();
    unsubScroll = undefined;
    themeObserver?.disconnect();
    themeObserver = undefined;
    activeAwareness?.setLocalStateField("cursor", null);
    activeAwareness = undefined;
    unregisterEditor(props.panelId);
    if (activeStateKey) {
      recordEditorPerf("codemirror_editor_destroyed", {
        documentId: props.documentId,
        stateKey: activeStateKey,
      });
    }
    view?.destroy();
    view = undefined;
    syncUndoManager?.destroy();
    undoManager?.destroy();
    undoManager = undefined;
    if (activeStateKey) {
      releaseYDoc(activeStateKey);
      activeStateKey = undefined;
    }
  }

  function hasRecentPointerFocusRequest() {
    return lastPointerFocusRequestAt > 0 && performance.now() - lastPointerFocusRequestAt < 1_000;
  }

  function scheduleEditorFocus() {
    const focus = () => {
      if (!view || props.readOnly || view.hasFocus) return;
      view.focus();
    };
    queueMicrotask(focus);
    requestAnimationFrame(focus);
    window.setTimeout(focus, 0);
  }

  function createEditor(stateKey: string) {
    if (!containerEl) return;

    const { yDoc, awareness } = acquireYDoc(stateKey);
    activeStateKey = stateKey;
    activeAwareness = awareness;
    const yText = ensureYDocMarkdownText(yDoc);
    undoManager = new Y.UndoManager(yText);
    const dark = isDarkMode();

    const startState = EditorState.create({
      doc: yText.toJSON(),
      extensions: [
        ...createBaseExtensions(),
        markdown(),
        pluginRendererSlotExtension({
          documentId: props.documentId,
          workspaceId: props.workspaceId,
        }),
        themeCompartment.of([
          dark ? darkTheme : lightTheme,
          syntaxHighlighting(markdownHighlighting),
        ]),
        editableCompartment.of(EditorView.editable.of(!props.readOnly)),
        yCollab(yText, awareness, {
          undoManager,
        }),
        ViewPlugin.fromClass(
          class {
            update(update: ViewUpdate) {
              if (!update.docChanged) return;
              const userEdit = update.transactions.some(
                (transaction) =>
                  transaction.isUserEvent("input") ||
                  transaction.isUserEvent("delete") ||
                  transaction.isUserEvent("undo") ||
                  transaction.isUserEvent("redo"),
              );
              props.onDocChange?.({
                persist: userEdit && update.view.hasFocus,
              });
            }
          },
        ),
        keymapCompartment.of(
          keymap.of([
            {
              key: "Mod-s",
              run: () => true,
            },
          ]),
        ),
      ],
    });

    view = new EditorView({
      state: startState,
      parent: containerEl,
      dispatchTransactions(trs) {
        const origin = view!.state.facet(ySyncFacet);
        yDoc.transact(() => {
          view!.update(trs);
        }, origin);
      },
    });

    let renderRefreshFrame: number | null = null;
    const clearRenderRefreshFrame = () => {
      if (renderRefreshFrame === null) return;
      cancelAnimationFrame(renderRefreshFrame);
      renderRefreshFrame = null;
    };
    const scheduleRenderRefresh = () => {
      clearRenderRefreshFrame();
      renderRefreshFrame = requestAnimationFrame(() => {
        renderRefreshFrame = null;
        if (!view) return;
        view.requestMeasure();
      });
    };
    const yTextRenderObserver = (_event: unknown, transaction?: { origin?: unknown }) => {
      if (transaction?.origin === view?.state.facet(ySyncFacet)) return;
      scheduleRenderRefresh();
    };
    yText.observe(yTextRenderObserver);
    cleanupYTextRenderRefresh = () => {
      clearRenderRefreshFrame();
      yText.unobserve(yTextRenderObserver);
    };

    const reconcileRemoteContent = () => {
      const editorView = view;
      if (!editorView || activeStateKey !== stateKey) return;
      const expectedText = yText.toJSON();
      const editorText = editorView.state.doc.toString();
      const renderedText = readRenderedCodeMirrorText(editorView);
      const editorMatches = editorText === expectedText;
      const renderedMatches = renderedText === expectedText;
      if (editorMatches && renderedMatches) return;
      if (editorView.composing) {
        recordEditorPerf("codemirror_remote_content_reconcile_deferred", {
          documentId: props.documentId,
          editorMatches,
          expectedLength: expectedText.length,
          renderedLength: renderedText.length,
          renderedMatches,
          stateKey,
        });
        return;
      }

      editorView.requestMeasure();
      const selection = editorView.state.selection.main;
      const shouldRestoreFocus = editorView.hasFocus || hasRecentPointerFocusRequest();
      recordEditorPerf(
        shouldRestoreFocus
          ? "codemirror_remote_content_reconcile_focused_recreate"
          : "codemirror_remote_content_reconcile_recreate",
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
      if (!view) return;
      const docLength = view.state.doc.length;
      view.dispatch({
        selection: {
          anchor: Math.min(selection.anchor, docLength),
          head: Math.min(selection.head, docLength),
        },
      });
      if (shouldRestoreFocus) scheduleEditorFocus();
    };

    if (hasRecentPointerFocusRequest()) {
      scheduleEditorFocus();
    }

    recordEditorPerf("codemirror_editor_created", {
      documentId: props.documentId,
      stateKey,
    });
    const scheduleRemoteContentReconcile = () => {
      clearRemoteContentReconcileTimer();
      view?.requestMeasure();
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

    const handleContainerPointerDown = (event: PointerEvent) => {
      if (props.readOnly || event.button !== 0) return;
      const target = event.target;
      if (!(target instanceof Node) || !containerEl?.contains(target)) return;
      lastPointerFocusRequestAt = performance.now();
      scheduleEditorFocus();
    };
    containerEl.addEventListener("pointerdown", handleContainerPointerDown);
    cleanupContainerFocus = () => {
      containerEl?.removeEventListener("pointerdown", handleContainerPointerDown);
    };

    registerEditor(props.panelId, new EditorApi(view, undoManager));

    view.contentDOM.addEventListener("paste", (e) => props.onEditorPaste?.(e));
    view.contentDOM.addEventListener("drop", (e) => props.onEditorDrop?.(e));

    const scroller = view.scrollDOM;
    const groupId = props.scrollGroupId;
    const handleScroll = () => {
      if (suppressScroll || !groupId) return;
      const maxScroll = scroller.scrollHeight - scroller.clientHeight;
      if (maxScroll <= 0) return;
      emitScrollSync(groupId, scroller.scrollTop / maxScroll, scrollSourceId);
    };
    scroller.addEventListener("scroll", handleScroll, { passive: true });

    if (groupId) {
      unsubScroll = onScrollSync(groupId, (ratio, sourceId) => {
        if (sourceId === scrollSourceId) return;
        const maxScroll = scroller.scrollHeight - scroller.clientHeight;
        if (maxScroll <= 0) return;
        suppressScroll = true;
        scroller.scrollTop = ratio * maxScroll;
        requestAnimationFrame(() => {
          suppressScroll = false;
        });
      });
    }

    themeObserver = new MutationObserver(() => {
      if (!view) return;
      const currentDark = isDarkMode();
      view.dispatch({
        effects: themeCompartment.reconfigure([
          currentDark ? darkTheme : lightTheme,
          syntaxHighlighting(markdownHighlighting),
        ]),
      });
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
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
      view.dispatch({
        effects: editableCompartment.reconfigure(EditorView.editable.of(!readOnly)),
      });
    }
  });

  onCleanup(destroyEditor);

  return (
    <div
      ref={(el) => {
        containerEl = el;
        createEditor(props.stateKey);
      }}
      class="h-full overflow-hidden"
      data-testid="document-editor"
    />
  );
}
