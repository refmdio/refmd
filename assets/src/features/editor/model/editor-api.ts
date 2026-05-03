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
      readOnly: boolean;
      reconnecting: boolean;
      sending: boolean;
      syncPaused: boolean;
    } | null;
  }
}
function installE2EEditorHook(): void {
  if (typeof window === "undefined" || !window.__REFMD_E2E__) return;
  window.__refmdGetDocumentSyncState = (documentId: string) => {
    for (const state of getAllActiveDocumentStates().values()) {
      if (state.documentId !== documentId) continue;
      return {
        autoSync: !!state.autoSync,
        channelState: state.channel?.state ?? null,
        error: state.error,
        initialized: state.initialized,
        readOnly: state.readOnly,
        reconnecting: state._reconnecting,
        sending: state.sending,
        syncPaused: state._syncPaused,
      };
    }
    return null;
  };
  window.__refmdSetEditorValueForDocument = (documentId: string, value: string) => {
    const editor = getEditorForDocument(documentId);
    if (editor) {
      editor.setValue(value);
    }
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
    return synced;
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
import { getAllActiveDocumentStates } from "./document-state/store";
