import type * as Y from "yjs";

export function readYDocMarkdownPreview(yDoc: Y.Doc): string {
  return yDoc.getText("content").toString();
}

export function ensureYDocMarkdownText(yDoc: Y.Doc): Y.Text {
  return yDoc.getText("content");
}
