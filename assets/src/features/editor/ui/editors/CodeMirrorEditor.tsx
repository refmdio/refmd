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
import { acquireYDoc, releaseYDoc } from "../../model/document-state/lifecycle";
import { emitScrollSync, onScrollSync } from "../../model/document-state/scroll";
import { registerEditor, unregisterEditor } from "../../model/editor-api";
import { EditorApi } from "../../model/codemirror-editor-api";
import "./codemirror-cursors.css";

interface ThemeColors {
  linkColor: string;
  monospaceBg: string;
  quoteColor: string;
  selectionOpacity: string;
}

const LIGHT_COLORS: ThemeColors = {
  linkColor: "#6e63d6",
  monospaceBg: "rgba(0,0,0,0.05)",
  quoteColor: "#596272",
  selectionOpacity: "0.2",
};

const DARK_COLORS: ThemeColors = {
  linkColor: "#8f86e8",
  monospaceBg: "rgba(255,255,255,0.05)",
  quoteColor: "#9aa1b0",
  selectionOpacity: "0.3",
};

function createEditorTheme(dark: boolean) {
  const colors = dark ? DARK_COLORS : LIGHT_COLORS;
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
        padding: "1rem",
        caretColor: "var(--foreground)",
      },
      ".cm-cursor": {
        borderLeftColor: "var(--foreground)",
      },
      ".cm-activeLine": {
        backgroundColor: "var(--muted)",
      },
      ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": {
        backgroundColor: "var(--accent)",
        opacity: colors.selectionOpacity,
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
    },
    { dark },
  );
}

function createHighlighting(dark: boolean) {
  const colors = dark ? DARK_COLORS : LIGHT_COLORS;
  return HighlightStyle.define([
    { tag: tags.heading1, fontWeight: "bold", fontSize: "1.5em" },
    { tag: tags.heading2, fontWeight: "bold", fontSize: "1.3em" },
    { tag: tags.heading3, fontWeight: "bold", fontSize: "1.1em" },
    { tag: tags.heading, fontWeight: "bold" },
    { tag: tags.emphasis, fontStyle: "italic" },
    { tag: tags.strong, fontWeight: "bold" },
    { tag: tags.link, color: colors.linkColor, textDecoration: "underline" },
    { tag: tags.url, color: colors.linkColor },
    {
      tag: tags.monospace,
      fontFamily: "var(--font-mono)",
      backgroundColor: colors.monospaceBg,
    },
    { tag: tags.quote, color: colors.quoteColor, fontStyle: "italic" },
    { tag: tags.strikethrough, textDecoration: "line-through" },
    { tag: tags.processingInstruction, color: colors.quoteColor },
  ]);
}

const lightTheme = createEditorTheme(false);
const darkTheme = createEditorTheme(true);
const lightHighlighting = createHighlighting(false);
const darkHighlighting = createHighlighting(true);

function isDarkMode(): boolean {
  return document.documentElement.classList.contains("dark");
}

function createBaseExtensions(): Extension[] {
  return [
    lineNumbers(),
    highlightActiveLineGutter(),
    highlightSpecialChars(),
    drawSelection(),
    dropCursor(),
    EditorState.allowMultipleSelections.of(true),
    indentOnInput(),
    bracketMatching(),
    highlightActiveLine(),
    keymap.of(yUndoManagerKeymap),
  ];
}

interface CodeMirrorEditorProps {
  documentId: string;
  panelId: string;
  scrollGroupId?: string;
  onDocChange?: () => void;
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
  let themeObserver: MutationObserver | undefined;
  let activeDocumentId: string | undefined;
  let unsubScroll: (() => void) | undefined;
  let suppressScroll = false;

  function destroyEditor() {
    unsubScroll?.();
    unsubScroll = undefined;
    themeObserver?.disconnect();
    themeObserver = undefined;
    unregisterEditor(props.panelId);
    view?.destroy();
    view = undefined;
    if (activeDocumentId) {
      releaseYDoc(activeDocumentId);
      activeDocumentId = undefined;
    }
  }

  function createEditor(documentId: string) {
    if (!containerEl) return;

    const { yDoc, awareness } = acquireYDoc(documentId);
    activeDocumentId = documentId;
    const yText = yDoc.getText("content");
    const undoManager = new Y.UndoManager(yText);
    const dark = isDarkMode();

    const startState = EditorState.create({
      doc: yText.toString(),
      extensions: [
        ...createBaseExtensions(),
        markdown(),
        themeCompartment.of([
          dark ? darkTheme : lightTheme,
          syntaxHighlighting(dark ? darkHighlighting : lightHighlighting),
        ]),
        editableCompartment.of(EditorView.editable.of(!props.readOnly)),
        yCollab(yText, awareness, {
          undoManager,
        }),
        ViewPlugin.fromClass(
          class {
            update(update: ViewUpdate) {
              if (update.docChanged) props.onDocChange?.();
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
          syntaxHighlighting(currentDark ? darkHighlighting : lightHighlighting),
        ]),
      });
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
  }

  createEffect(() => {
    const documentId = props.documentId;
    if (activeDocumentId === documentId) return;
    destroyEditor();
    createEditor(documentId);
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
        createEditor(props.documentId);
      }}
      class="h-full overflow-hidden"
      data-testid="document-editor"
    />
  );
}
