import * as Y from "yjs";

export interface EditorPosition {
  line: number;
  ch: number;
}
export interface EditorRange {
  from: EditorPosition;
  to: EditorPosition;
}
export interface EditorSelection {
  anchor: EditorPosition;
  head: EditorPosition;
}
export type EditorPluginDecorationStyle = "highlight" | "underline" | "gutter_marker";
export type EditorPluginDecorationTone = "neutral" | "info" | "warning";
export interface EditorPluginDecoration {
  id: string;
  range: {
    from: number;
    to: number;
  };
  style: EditorPluginDecorationStyle;
  tone: EditorPluginDecorationTone;
}
interface EditorChange {
  from: EditorPosition;
  to?: EditorPosition;
  text: string;
}
export interface EditorTransaction {
  changes?: EditorChange[];
  selection?: {
    anchor: EditorPosition;
    head?: EditorPosition;
  };
  replaceSelection?: string;
}
export interface EditorLike {
  getValue(): string;
  setValue(value: string): void;
  getLine(line: number): string;
  setLine(line: number, text: string): void;
  lineCount(): number;
  getSelection(): string;
  somethingSelected(): boolean;
  replaceSelection(text: string): void;
  getRange(from: EditorPosition, to: EditorPosition): string;
  replaceRange(text: string, from: EditorPosition, to?: EditorPosition): void;
  transaction(tx: EditorTransaction): void;
  getCursor(side?: "from" | "to" | "head" | "anchor"): EditorPosition;
  setCursor(pos: EditorPosition): void;
  setSelection(anchor: EditorPosition, head?: EditorPosition): void;
  listSelections(): EditorSelection[];
  getScrollInfo(): {
    top: number;
    left: number;
  };
  scrollTo(x?: number | null, y?: number | null): void;
  scrollIntoView(range: EditorRange, center?: boolean): void;
  undo(): void;
  redo(): void;
  focus(): void;
  blur(): void;
  hasFocus(): boolean;
  posToOffset(pos: EditorPosition): number;
  offsetToPos(offset: number): EditorPosition;
  setPluginDecorations(sourceId: string, decorations: readonly EditorPluginDecoration[]): void;
  clearPluginDecorations(sourceId: string): void;
}
const editorRegistry = new Map<string, EditorLike>();
let onEditorRegistered: (() => void) | null = null;
declare global {
  interface Window {
    __REFMD_E2E__?: boolean;
    __refmdSetEditorValueForDocument?: (documentId: string, value: string) => boolean;
    __refmdGetDocumentSyncState?: (documentId: string) => {
      autoSync: boolean;
      channelState: string | null;
      error: string | null;
      initialized: boolean;
      candidates: Array<{
        autoSync: boolean;
        channelState: string | null;
        error: string | null;
        initialized: boolean;
        loadedFromOfflineCache: boolean;
        readOnly: boolean;
        refCount: number;
        savedText: string | null;
        stateKey: string;
        syncPaused: boolean;
        text: string;
      }>;
      loadedFromOfflineCache: boolean;
      pendingSave: boolean;
      pendingSaveWatchdogAgeMs: number | null;
      pendingSaveWatchdogKind: "update" | "snapshot" | null;
      pendingSnapshot: boolean;
      pendingSnapshotEnvelope: boolean;
      pendingUpdate: boolean;
      pendingUpdateBytes: boolean;
      pendingUpdateEnvelope: boolean;
      readOnly: boolean;
      recentSaveEvents: unknown[];
      reconnecting: boolean;
      savedText: string | null;
      sending: boolean;
      stateKey: string;
      syncPaused: boolean;
      text: string;
      unsavedCanonicalText: boolean;
    } | null;
    __refmdGetDocumentText?: (documentId: string) => string | null;
    __refmdFlushDocumentSync?: (documentId: string) => Promise<boolean>;
    __refmdAppendDocumentText?: (documentId: string, text: string) => boolean;
    __refmdSetEditorSelectionForDocument?: (
      documentId: string,
      anchorOffset: number,
      headOffset: number,
    ) => boolean;
  }
}
function installE2EEditorHook(): void {
  if (typeof window === "undefined" || !window.__REFMD_E2E__) return;
  const panelBelongsToState = (stateKey: string, panelId: string | null | undefined) =>
    !!panelId && (panelId === stateKey || panelId.startsWith(`${stateKey}:`));
  const panelBelongsToDocument = (panelId: string, documentId: string) =>
    panelId.startsWith(`${documentId}:`) || panelId.includes(`:${documentId}:`);
  const findDocumentState = (documentId: string) => {
    const states = [...getAllActiveDocumentStates().values()];
    const matchingStates = states.filter((item) => item.documentId === documentId);
    const focusedPanelId = focusedPanelIdAccessor?.();
    const focusedState = matchingStates.find((item) =>
      panelBelongsToState(item.stateKey, focusedPanelId),
    );
    if (
      focusedState?.autoSync &&
      !focusedState.readOnly &&
      focusedState.channel?.state === "joined"
    ) {
      return focusedState;
    }
    return (
      matchingStates.find(
        (item) => item.autoSync && !item.readOnly && item.channel?.state === "joined",
      ) ??
      focusedState ??
      matchingStates.find((item) => item.autoSync && !item.readOnly) ??
      matchingStates.find((item) => item.channel?.state === "joined") ??
      matchingStates[0] ??
      (states.length === 1 ? states[0] : null)
    );
  };
  const getCandidateDiagnostics = (documentId: string) =>
    [...getAllActiveDocumentStates().values()]
      .filter((item) => item.documentId === documentId)
      .map((item) => {
        let savedText: string | null = null;
        if (item.lastSavedState) {
          const savedDoc = new Y.Doc();
          try {
            Y.applyUpdate(savedDoc, item.lastSavedState, "remote");
            savedText = savedDoc.getText("content").toString();
          } finally {
            savedDoc.destroy();
          }
        }
        return {
          autoSync: !!item.autoSync,
          channelState: item.channel?.state ?? null,
          error: item.error,
          initialized: item.initialized,
          loadedFromOfflineCache: item.loadedFromOfflineCache,
          readOnly: item.readOnly,
          refCount: item.refCount,
          savedText,
          stateKey: item.stateKey,
          syncPaused: item._syncPaused,
          text: item.yDoc.getText("content").toString(),
        };
      });
  window.__refmdGetDocumentSyncState = (documentId: string) => {
    const state = findDocumentState(documentId);
    if (state) {
      const text = state.yDoc.getText("content").toString();
      let savedText: string | null = null;
      if (state.lastSavedState) {
        const savedDoc = new Y.Doc();
        try {
          Y.applyUpdate(savedDoc, state.lastSavedState, "remote");
          savedText = savedDoc.getText("content").toString();
        } finally {
          savedDoc.destroy();
        }
      }
      return {
        autoSync: !!state.autoSync,
        candidates: getCandidateDiagnostics(documentId),
        channelState: state.channel?.state ?? null,
        error: state.error,
        initialized: state.initialized,
        loadedFromOfflineCache: state.loadedFromOfflineCache,
        pendingSave: state.sending && state.pendingSaveTimeout !== null,
        pendingSaveWatchdogAgeMs:
          state._pendingSaveWatchdogStartedAt === null
            ? null
            : Date.now() - state._pendingSaveWatchdogStartedAt,
        pendingSaveWatchdogKind: state._pendingSaveWatchdogKind,
        pendingSnapshot: state.pendingSnapshot !== null || state.pendingSnapshotEnvelope !== null,
        pendingSnapshotEnvelope: state.pendingSnapshotEnvelope !== null,
        pendingUpdate: state.pendingUpdateEnvelope !== null || state.pendingUpdateBytes !== null,
        pendingUpdateBytes: state.pendingUpdateBytes !== null,
        pendingUpdateEnvelope: state.pendingUpdateEnvelope !== null,
        readOnly: state.readOnly,
        recentSaveEvents: state._recentSaveEvents.slice(-8),
        reconnecting: state._reconnecting,
        savedText,
        sending: state.sending,
        stateKey: state.stateKey,
        syncPaused: state._syncPaused,
        text,
        unsavedCanonicalText: savedText === null ? text.length > 0 : text !== savedText,
      };
    }
    return null;
  };
  window.__refmdGetDocumentText = (documentId: string) => {
    const state = findDocumentState(documentId);
    return state?.yDoc.getText("content").toString() ?? null;
  };
  window.__refmdFlushDocumentSync = async (documentId: string) => {
    const states = [...getAllActiveDocumentStates().values()].filter(
      (item) => item.documentId === documentId && item.autoSync && !item.readOnly,
    );
    if (states.length === 0) return false;
    await Promise.all(states.map((state) => state.autoSync?.flushNow()));
    return true;
  };
  window.__refmdAppendDocumentText = (documentId: string, text: string) => {
    const state = findDocumentState(documentId);
    if (!state?.autoSync) return false;
    const yText = state.yDoc.getText("content");
    state.yDoc.transact(() => {
      yText.insert(yText.length, text);
    });
    state.autoSync.notifyLocalEdit();
    return true;
  };
  window.__refmdSetEditorValueForDocument = (documentId: string, value: string) => {
    let synced = false;
    for (const state of getAllActiveDocumentStates().values()) {
      if (state.documentId !== documentId) continue;
      if (!state.autoSync) continue;
      const yText = state.yDoc.getText("content");
      state.yDoc.transact(() => {
        yText.delete(0, yText.length);
        yText.insert(0, value);
      });
      state.autoSync.notifyLocalEdit();
      synced = true;
    }
    if (synced) return true;

    let editorSynced = false;
    for (const [panelId, editor] of editorRegistry) {
      if (!panelBelongsToDocument(panelId, documentId)) continue;
      if (editor.getValue() !== value) {
        editor.setValue(value);
      }
      editorSynced = true;
    }
    return editorSynced;
  };
  window.__refmdSetEditorSelectionForDocument = (documentId, anchorOffset, headOffset) => {
    let selected = false;
    for (const [panelId, editor] of editorRegistry) {
      if (!panelBelongsToDocument(panelId, documentId)) continue;
      const maxOffset = editor.getValue().length;
      const anchor = Math.max(0, Math.min(maxOffset, Math.trunc(anchorOffset)));
      const head = Math.max(0, Math.min(maxOffset, Math.trunc(headOffset)));
      editor.focus();
      editor.setSelection(editor.offsetToPos(anchor), editor.offsetToPos(head));
      selected = editor.somethingSelected() || selected;
    }
    return selected;
  };
}
export function setOnEditorRegistered(cb: () => void): void {
  onEditorRegistered = cb;
}
let focusedPanelIdAccessor: (() => string | null) | null = null;
export function setFocusedPanelIdAccessor(accessor: () => string | null): void {
  focusedPanelIdAccessor = accessor;
}
export function registerEditor(panelId: string, api: EditorLike): void {
  editorRegistry.set(panelId, api);
  installE2EEditorHook();
  onEditorRegistered?.();
}
export function unregisterEditor(panelId: string): void {
  editorRegistry.delete(panelId);
}
export function getEditor(panelId: string): EditorLike | null {
  return editorRegistry.get(panelId) ?? null;
}
export function getEditorForDocument(documentId: string): EditorLike | null {
  for (const [panelId, api] of editorRegistry) {
    if (panelId.startsWith(documentId + ":")) {
      return api;
    }
  }
  return null;
}
export function getActiveEditor(): EditorLike | null {
  const panelId = focusedPanelIdAccessor?.();
  if (!panelId) return null;
  return editorRegistry.get(panelId) ?? null;
}
export function getActiveEditorEntry(): { panelId: string; editor: EditorLike } | null {
  const panelId = focusedPanelIdAccessor?.();
  if (!panelId) return null;
  const editor = editorRegistry.get(panelId);
  return editor ? { panelId, editor } : null;
}
import { getAllActiveDocumentStates } from "../document-state/store";
