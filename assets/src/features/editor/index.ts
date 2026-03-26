export { CodeMirrorEditor } from "./ui/editors/CodeMirrorEditor";
export { ProseMirrorEditor } from "./ui/editors/ProseMirrorEditor";
export { PresenceAvatars } from "./ui/PresenceAvatars";
export {
  EditorApi,
  ProseMirrorEditorApi,
  registerEditor,
  unregisterEditor,
  getEditor,
  getActiveEditor,
  getEditorForDocument,
  setFocusedPanelIdAccessor,
  setOnEditorRegistered,
} from "./lib/editor-api";
export { getDocText } from "./lib/ydoc-cache";
export {
  acquireDocumentState,
  releaseDocumentState,
  getDocumentState,
  getDocumentError,
  getDocumentAwareness,
} from "./lib/document-state-cache";
export { initializeDocumentSync } from "./lib/document-sync";
export type {
  EditorLike,
  EditorPosition,
  EditorRange,
  EditorSelection,
  EditorTransaction,
} from "./lib/editor-api";
