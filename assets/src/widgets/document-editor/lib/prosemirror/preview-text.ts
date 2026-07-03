import type * as Y from "yjs";
import { yXmlFragmentToProseMirrorRootNode } from "y-prosemirror";
import { proseMirrorDocToMarkdown } from "./markdown-to";
import { markdownSchema } from "./schema";

const PROSEMIRROR_BLOCK_NODE_NAMES = new Set([
  "blockquote",
  "bullet_list",
  "code_block",
  "heading",
  "horizontal_rule",
  "list_item",
  "ordered_list",
  "paragraph",
]);

function appendXmlTextBoundary(parts: string[]) {
  if (parts.length === 0) return;
  const last = parts[parts.length - 1] ?? "";
  if (!last.endsWith("\n")) parts.push("\n");
}

function readXmlNodeText(node: unknown, parts: string[]) {
  const xmlNode = node as {
    nodeName?: string;
    toArray?: () => unknown[];
    toString?: () => string;
  };
  if (typeof xmlNode.toArray === "function") {
    const isBlock =
      typeof xmlNode.nodeName === "string" && PROSEMIRROR_BLOCK_NODE_NAMES.has(xmlNode.nodeName);
    if (isBlock) appendXmlTextBoundary(parts);
    for (const child of xmlNode.toArray()) readXmlNodeText(child, parts);
    if (isBlock) appendXmlTextBoundary(parts);
    return;
  }

  const text = xmlNode.toString?.() ?? "";
  if (text.length > 0) parts.push(text);
}

function readProseMirrorXmlFallbackText(fragment: Y.XmlFragment): string {
  const parts: string[] = [];
  for (const node of fragment.toArray()) readXmlNodeText(node, parts);
  return parts
    .join("")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function readProseMirrorMarkdown(fragment: Y.XmlFragment): string {
  if (fragment.length === 0) return "";

  try {
    const doc = yXmlFragmentToProseMirrorRootNode(fragment, markdownSchema);
    const markdown = proseMirrorDocToMarkdown(doc);
    if (markdown.trim().length > 0) return markdown;
  } catch {
    // Fall back to text extraction below so legacy/unknown XML never renders as a blank preview.
  }

  return readProseMirrorXmlFallbackText(fragment);
}

export function readYDocMarkdownPreview(yDoc: Y.Doc): string {
  const sharedText = yDoc.getText("content").toString();
  if (sharedText.trim().length > 0) return sharedText;

  return readProseMirrorMarkdown(yDoc.getXmlFragment("prosemirror"));
}

export function ensureYDocMarkdownText(yDoc: Y.Doc): Y.Text {
  const sharedText = yDoc.getText("content");
  if (sharedText.length > 0) return sharedText;

  const markdown = readProseMirrorMarkdown(yDoc.getXmlFragment("prosemirror"));
  if (markdown.trim().length === 0) return sharedText;

  yDoc.transact(() => {
    if (sharedText.length === 0) sharedText.insert(0, markdown);
  }, "bridge:prosemirror-markdown-bootstrap");

  return sharedText;
}
