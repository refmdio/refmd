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
      accessKind: "workspace" | "share";
      activeSnapshotId: string | null;
      autoSync: boolean;
      cacheRestore: {
        accessKind: "workspace" | "share";
        attemptedAt: number;
        restored: boolean;
        reason: string | null;
      } | null;
      channelState: string | null;
      confirmedClocks: Record<string, number>;
      documentId: string;
      error: string | null;
      hasLastSavedState: boolean;
      hasSnapshotCiphertextHash: boolean;
      hasSnapshotProofHash: boolean;
      initialized: boolean;
      keyVersion: number;
      joinDecision: {
        hasLastSavedState: boolean;
        hasSnapshotCiphertextHash: boolean;
        hasSnapshotProofHash: boolean;
        knownSnapshotId: string | null;
        pinSnapshotId: string | null;
        stateSnapshotId: string | null;
        useDelta: boolean;
      } | null;
      lastJoinMode: "complete" | "delta";
      candidates: Array<{
        accessKind: "workspace" | "share";
        activeSnapshotId: string | null;
        autoSync: boolean;
        cacheRestore: {
          accessKind: "workspace" | "share";
          attemptedAt: number;
          restored: boolean;
          reason: string | null;
        } | null;
        channelState: string | null;
        confirmedClocks: Record<string, number>;
        documentId: string;
        error: string | null;
        hasLastSavedState: boolean;
        hasSnapshotCiphertextHash: boolean;
        hasSnapshotProofHash: boolean;
        initialized: boolean;
        keyVersion: number;
        joinDecision: {
          hasLastSavedState: boolean;
          hasSnapshotCiphertextHash: boolean;
          hasSnapshotProofHash: boolean;
          knownSnapshotId: string | null;
          pinSnapshotId: string | null;
          stateSnapshotId: string | null;
          useDelta: boolean;
        } | null;
        lastJoinMode: "complete" | "delta";
        loadedFromOfflineCache: boolean;
        readOnly: boolean;
        refCount: number;
        savedText: string | null;
        stateKey: string;
        syncPaused: boolean;
        text: string;
        writeSessionError: string | null;
        writeSessionPreparing: boolean;
        writeSessionReady: boolean;
        writeSessionReadyAt: number | null;
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
      writeSessionError: string | null;
      writeSessionPreparing: boolean;
      writeSessionReady: boolean;
      writeSessionReadyAt: number | null;
    } | null;
    __refmdGetDocumentText?: (documentId: string) => string | null;
    __refmdFlushDocumentSync?: (documentId: string) => Promise<boolean>;
    __refmdAppendDocumentText?: (documentId: string, text: string) => boolean;
    __refmdGetEditorValuesForDocument?: (documentId: string) => Array<{
      focused: boolean;
      lineCount: number;
      panelId: string;
      value: string;
    }>;
    __refmdSetEditorSelectionForDocument?: (
      documentId: string,
      anchorOffset: number,
      headOffset: number,
    ) => boolean;
  }
}

function readE2EDocumentText(doc: Y.Doc): string {
  return doc.getText("content").toString();
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
  const isWriteSessionReady = (state: ReturnType<typeof findDocumentState>) =>
    !!state?.writeSession &&
    state.writeSessionReadyAt !== null &&
    !state._admissionDirectoryRefreshRequired &&
    state.writeSession.expiresAtMs - 5_000 > Date.now();
  const getCandidateDiagnostics = (documentId: string) =>
    [...getAllActiveDocumentStates().values()]
      .filter((item) => item.documentId === documentId)
      .map((item) => {
        let savedText: string | null = null;
        if (item.lastSavedState) {
          const savedDoc = new Y.Doc();
          try {
            Y.applyUpdate(savedDoc, item.lastSavedState, "remote");
            savedText = readE2EDocumentText(savedDoc);
          } finally {
            savedDoc.destroy();
          }
        }
        return {
          accessKind: item.access.kind,
          activeSnapshotId: item.activeSnapshotId,
          autoSync: !!item.autoSync,
          cacheRestore: item._lastCacheRestore,
          channelState: item.channel?.state ?? null,
          confirmedClocks: { ...item.confirmedClocks },
          documentId: item.documentId,
          error: item.error,
          hasLastSavedState: item.lastSavedState !== null,
          hasSnapshotCiphertextHash: item.snapshotCiphertextHash.length > 0,
          hasSnapshotProofHash: item.snapshotProofHash.length > 0,
          initialized: item.initialized,
          keyVersion: item.keyVersion,
          joinDecision: item._lastJoinDecision,
          lastJoinMode: item._lastJoinMode,
          loadedFromOfflineCache: item.loadedFromOfflineCache,
          readOnly: item.readOnly,
          refCount: item.refCount,
          savedText,
          stateKey: item.stateKey,
          syncPaused: item._syncPaused,
          text: readE2EDocumentText(item.yDoc),
          writeSessionError: item.writeSessionError,
          writeSessionPreparing: item.writeSessionPromise !== null,
          writeSessionReady: isWriteSessionReady(item),
          writeSessionReadyAt: item.writeSessionReadyAt,
        };
      });
  window.__refmdGetDocumentSyncState = (documentId: string) => {
    const state = findDocumentState(documentId);
    if (state) {
      const text = readE2EDocumentText(state.yDoc);
      let savedText: string | null = null;
      if (state.lastSavedState) {
        const savedDoc = new Y.Doc();
        try {
          Y.applyUpdate(savedDoc, state.lastSavedState, "remote");
          savedText = readE2EDocumentText(savedDoc);
        } finally {
          savedDoc.destroy();
        }
      }
      return {
        accessKind: state.access.kind,
        activeSnapshotId: state.activeSnapshotId,
        autoSync: !!state.autoSync,
        cacheRestore: state._lastCacheRestore,
        candidates: getCandidateDiagnostics(documentId),
        channelState: state.channel?.state ?? null,
        confirmedClocks: { ...state.confirmedClocks },
        documentId: state.documentId,
        error: state.error,
        hasLastSavedState: state.lastSavedState !== null,
        hasSnapshotCiphertextHash: state.snapshotCiphertextHash.length > 0,
        hasSnapshotProofHash: state.snapshotProofHash.length > 0,
        initialized: state.initialized,
        keyVersion: state.keyVersion,
        joinDecision: state._lastJoinDecision,
        lastJoinMode: state._lastJoinMode,
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
        writeSessionError: state.writeSessionError,
        writeSessionPreparing: state.writeSessionPromise !== null,
        writeSessionReady: isWriteSessionReady(state),
        writeSessionReadyAt: state.writeSessionReadyAt,
      };
    }
    return null;
  };
  window.__refmdGetDocumentText = (documentId: string) => {
    const state = findDocumentState(documentId);
    return state ? readE2EDocumentText(state.yDoc) : null;
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
  window.__refmdGetEditorValuesForDocument = (documentId: string) =>
    [...editorRegistry.entries()]
      .filter(([panelId]) => panelBelongsToDocument(panelId, documentId))
      .map(([panelId, editor]) => ({
        focused: editor.hasFocus(),
        lineCount: editor.lineCount(),
        panelId,
        value: editor.getValue(),
      }));
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
