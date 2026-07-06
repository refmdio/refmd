import * as Y from "yjs";
import { encodeCanonicalDiffAsUpdate } from "@/shared/lib/yjs/canonical-document";
import type { DocumentState } from "../../model/document-state/types";

export type ExistingSnapshotCanonicalUpdate =
  | { kind: "update"; update: Uint8Array }
  | { kind: "empty" }
  | { kind: "missing_baseline" }
  | { kind: "structural_unavailable" };

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

export function encodeExistingSnapshotCanonicalUpdate(
  state: DocumentState,
): ExistingSnapshotCanonicalUpdate {
  if (!state.lastSavedState) return { kind: "missing_baseline" };

  const update = encodeCanonicalDiffAsUpdate(state.yDoc, state.lastSavedState);
  if (!update) return { kind: "structural_unavailable" };
  if (update.length <= 2) return { kind: "empty" };
  return { kind: "update", update };
}
