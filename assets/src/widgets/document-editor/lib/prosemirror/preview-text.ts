import type * as Y from "yjs";

export function readYDocMarkdownPreview(yDoc: Y.Doc): string {
  return yDoc.getText("content").toJSON();
}

export function ensureYDocMarkdownText(yDoc: Y.Doc): Y.Text {
  return yDoc.getText("content");
}
