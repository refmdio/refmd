import type * as Y from "yjs";
import { yXmlFragmentToProseMirrorRootNode } from "y-prosemirror";
import { proseMirrorDocToMarkdown } from "./markdown-to";
import { markdownSchema } from "./schema";

export function readYDocMarkdownPreview(yDoc: Y.Doc): string {
  const sharedText = yDoc.getText("content").toString();
  if (sharedText.trim().length > 0) return sharedText;

  const sharedProseMirror = yDoc.getXmlFragment("prosemirror");
  if (sharedProseMirror.length === 0) return "";

  try {
    const doc = yXmlFragmentToProseMirrorRootNode(sharedProseMirror, markdownSchema);
    return proseMirrorDocToMarkdown(doc);
  } catch {
    return "";
  }
}
