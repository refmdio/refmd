import * as Y from "yjs";
import type { DocumentState } from "../../../model/document-state/types";

function textFromUpdate(update: Uint8Array | null): string | null {
  if (!update) return null;
  const doc = new Y.Doc();
  try {
    Y.applyUpdate(doc, update, "remote");
    return doc.getText("content").toString();
  } finally {
    doc.destroy();
  }
}

export function hasUnsavedCanonicalText(state: DocumentState): boolean {
  const current = state.yDoc.getText("content").toString();
  const saved = textFromUpdate(state.lastSavedState);
  return saved === null ? current.length > 0 : current !== saved;
}

export function refreshSavedBaselineToCurrent(state: DocumentState): void {
  state.lastSavedState = Y.encodeStateAsUpdate(state.yDoc);
}
