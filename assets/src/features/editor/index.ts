export { CodeMirrorEditor } from "./ui/editors/CodeMirrorEditor";
export { ProseMirrorEditor } from "./ui/editors/ProseMirrorEditor";
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
export type {
  EditorLike,
  EditorPosition,
  EditorRange,
  EditorSelection,
  EditorTransaction,
} from "./lib/editor-api";
