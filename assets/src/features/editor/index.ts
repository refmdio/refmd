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
  needsReauth,
  completeReauth,
  requestReauth,
  getRollbackWarning,
  approveRollback,
} from "./lib/document-state-cache";
export { initializeDocumentSync } from "./lib/document-sync";
export {
  initializeDocumentFromCache,
  restoreDocumentStateFromCache,
} from "./lib/document-offline-init";
export { OfflineIndicator } from "./ui/OfflineIndicator";
export { setupFlushHooks } from "./lib/flush-hooks";
export { syncPendingDocuments } from "./lib/offline-pending-sync";
export type {
  EditorLike,
  EditorPosition,
  EditorRange,
  EditorSelection,
  EditorTransaction,
} from "./lib/editor-api";
