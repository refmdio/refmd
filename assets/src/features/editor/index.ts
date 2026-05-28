export { PresenceAvatars } from "./ui/presence/PresenceAvatars";
export {
  getEditor,
  getActiveEditor,
  getActiveEditorEntry,
  getEditorForDocument,
  registerEditor,
  setFocusedPanelIdAccessor,
  setOnEditorRegistered,
  unregisterEditor,
} from "./model/editor/editor-api";
export type {
  EditorLike,
  EditorPluginDecoration,
  EditorPluginDecorationStyle,
  EditorPluginDecorationTone,
  EditorPosition,
  EditorRange,
  EditorSelection,
  EditorTransaction,
} from "./model/editor/editor-api";
export { acquireDocumentState, getDocumentState, getDocText } from "./model/document-state/store";
export {
  acquireYDoc,
  clearAllDocumentStates,
  releaseDocumentState,
  releaseYDoc,
  resetDocumentState,
} from "./model/document-state/lifecycle";
export { emitScrollSync, onScrollSync } from "./model/document-state/scroll";
export {
  clearShareReentry,
  completeReauth,
  getDocumentAwareness,
  getDocumentError,
  getDocumentReadOnly,
  getDocumentSyncPaused,
  needsShareReentry,
  needsReauth,
  requestShareReentry,
  setDocumentReadOnly,
  setDocumentSyncPaused,
} from "./model/document-state/signals";
export { initializeDocumentSync } from "./lib/sync/initialize";
export { initializeDocumentTile } from "./lib/sync/bootstrap-tile-lifecycle";
export { canBufferDisconnectedChanges, isDocumentSyncReady } from "./lib/sync/readiness";
export { retainUxLimitNotice } from "./lib/sync/ux-limit-notice";
export { installPublicationRenameAutoSync } from "./lib/sync/outbound-publication";
export { buildDeviceKeyCaches } from "./lib/sync/inbound-signing-keys";
export { createDocumentOffline } from "./lib/offline/create";
export { syncOfflineCreatedDocuments } from "./lib/offline/sync-created";
export { syncPendingDocuments } from "./lib/offline/pending-sync";
export { OfflineIndicator } from "./ui/status/OfflineIndicator";
export { setupFlushHooks } from "./lib/offline/flush-hooks";
export {
  clearRegisteredDocumentAccess,
  registerSharedDocumentAccess,
} from "./model/document-state/access";
export {
  activateSharedDocumentRoute,
  disposeSharedDocumentRoute,
} from "./model/document-state/share-route";
