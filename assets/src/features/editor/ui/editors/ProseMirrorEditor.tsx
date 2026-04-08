import { createEffect, createSignal, onCleanup, Show } from "solid-js";
import { EditorView } from "prosemirror-view";
import { EditorState, type Plugin } from "prosemirror-state";
import * as Y from "yjs";
import { acquireYDoc, releaseYDoc } from "../../model/document-state/lifecycle";
import { emitScrollSync, onScrollSync } from "../../model/document-state/scroll";
import { registerEditor, unregisterEditor } from "../../model/editor-api";
import { ProseMirrorEditorApi } from "../../model/prosemirror-editor-api";
import { markdownSchema } from "../../lib/prosemirror/schema";
import { buildCollabPlugins } from "../../lib/prosemirror/plugins/base";
import { setupCollabPlugins } from "../../lib/prosemirror/plugins/collab";
import { blockHandlePlugin } from "../../lib/prosemirror/plugins/block-handle";
import { placeholderPlugin } from "../../lib/prosemirror/plugins/placeholder";
import { INACTIVE, slashCommandsPlugin } from "../../lib/prosemirror/plugins/slash-commands";
import type { SlashCommand, SlashMenuState } from "../../lib/prosemirror/plugins/slash-commands";
import { SlashMenu } from "./SlashMenu";
import { FloatingToolbar } from "./FloatingToolbar";

import "./prosemirror-editor.css";

interface ProseMirrorEditorProps {
  documentId: string;
  panelId: string;
  scrollGroupId?: string;
  onDocChange?: () => void;
  onEditorPaste?: (evt: ClipboardEvent) => void;
  onEditorDrop?: (evt: DragEvent) => void;
  readOnly?: boolean;
}

export function ProseMirrorEditor(props: ProseMirrorEditorProps) {
  const scrollSourceId = `pm-${Math.random().toString(36).slice(2)}`;
  let containerEl: HTMLDivElement | undefined;
  let view: EditorView | undefined;
  let slashPlugin: Plugin | null = null;
  let activeDocumentId: string | undefined;
  let cleanupViewListeners: (() => void) | undefined;
  let destroyCollab: (() => void) | undefined;
  let unsubScroll: (() => void) | undefined;
  let suppressScroll = false;

  const [slashState, setSlashState] = createSignal<SlashMenuState>(INACTIVE);
  const [hasSelection, setHasSelection] = createSignal(false);
  const [selectionVersion, setSelectionVersion] = createSignal(0);
  const [currentView, setCurrentView] = createSignal<EditorView | null>(null);

  function destroyEditor() {
    cleanupViewListeners?.();
    cleanupViewListeners = undefined;
    unsubScroll?.();
    unsubScroll = undefined;
    destroyCollab?.();
    destroyCollab = undefined;
    unregisterEditor(props.panelId);
    view?.destroy();
    view = undefined;
    setCurrentView(null);
    slashPlugin = null;
    if (activeDocumentId) {
      releaseYDoc(activeDocumentId);
      activeDocumentId = undefined;
    }
  }

  function createEditor(documentId: string) {
    if (!containerEl) return;
    const rootEl = containerEl;

    const { yDoc, awareness } = acquireYDoc(documentId);
    activeDocumentId = documentId;

    const collab = setupCollabPlugins({
      yDoc,
      schema: markdownSchema,
      awareness,
    });

    destroyCollab = collab.destroy;

    const sp = slashCommandsPlugin(markdownSchema);
    slashPlugin = sp;

    let destroyed = false;

    const editorPlugins = [...collab.plugins, ...buildCollabPlugins(markdownSchema)];
    if (!props.readOnly) {
      editorPlugins.push(placeholderPlugin(), sp, blockHandlePlugin());
    }

    const state = EditorState.create({
      doc: collab.doc,
      plugins: editorPlugins,
    });

    const editorView = new EditorView(containerEl, {
      state,
      editable: () => !props.readOnly,
      dispatchTransaction(tr) {
        if (destroyed) return;

        const newState = editorView.state.apply(tr);
        editorView.updateState(newState);

        if (tr.docChanged) {
          props.onDocChange?.();
        }

        const ss = sp.getState(newState) as SlashMenuState | undefined;
        setSlashState(ss ?? INACTIVE);

        const { from, to } = newState.selection;
        const hasSel = from !== to && editorView.hasFocus();
        setHasSelection(hasSel);
        if (hasSel) setSelectionVersion((v) => v + 1);
      },
    });

    view = editorView;
    setCurrentView(editorView);
    const yText = yDoc.getText("content");
    const undoMgr = new Y.UndoManager(yText);
    registerEditor(props.panelId, new ProseMirrorEditorApi(editorView, yText, undoMgr));

    const handlePaste = (event: ClipboardEvent) => props.onEditorPaste?.(event);
    const handleDrop = (event: DragEvent) => props.onEditorDrop?.(event);

    editorView.dom.addEventListener("paste", handlePaste);
    editorView.dom.addEventListener("drop", handleDrop);

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
      rootEl.removeEventListener("scroll", handleScroll);
    };
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
      view.setProps({ editable: () => !readOnly });
    }
  });

  onCleanup(destroyEditor);

  function handleSlashSelect(cmd: SlashCommand) {
    if (!view || !slashPlugin) return;

    const ss = slashPlugin.getState(view.state) as SlashMenuState | undefined;
    if (!ss?.active) return;

    const key = slashPlugin.spec.key!;
    const from = ss.pos;
    const to = view.state.selection.from;

    if (to > from) {
      view.dispatch(view.state.tr.delete(from, to).setMeta(key, INACTIVE));
    } else {
      view.dispatch(view.state.tr.setMeta(key, INACTIVE));
    }

    const v = view;
    queueMicrotask(() => {
      cmd.execute(v);
      v.focus();
    });
  }

  return (
    <>
      <div
        ref={(el) => {
          containerEl = el;
          createEditor(props.documentId);
        }}
        class="h-full overflow-auto relative"
      />
      <Show when={!props.readOnly && currentView() && slashState().active}>
        <SlashMenu view={currentView()!} slashState={slashState()} onSelect={handleSlashSelect} />
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
