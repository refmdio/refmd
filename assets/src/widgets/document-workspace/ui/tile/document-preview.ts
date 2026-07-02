import { getDocumentState } from "@/features/editor";
import type * as Y from "yjs";

const PREVIEW_BLOCK_NODE_NAMES = new Set([
  "blockquote",
  "code_block",
  "heading",
  "list_item",
  "ordered_list",
  "paragraph",
  "bullet_list",
]);

function appendBoundary(parts: string[]): void {
  if (parts.length === 0) return;
  const last = parts[parts.length - 1] ?? "";
  if (last.endsWith("\n")) return;
  parts.push("\n");
}

type XmlPreviewNode = Y.XmlElement | Y.XmlText | Y.XmlHook;

function readXmlNodeText(node: XmlPreviewNode, parts: string[]): void {
  const children = (node as { toArray?: () => XmlPreviewNode[] }).toArray;
  if (typeof children === "function") {
    const nodeName = (node as { nodeName?: string }).nodeName;
    const isBlock = typeof nodeName === "string" && PREVIEW_BLOCK_NODE_NAMES.has(nodeName);
    if (isBlock) appendBoundary(parts);
    for (const child of children.call(node)) {
      readXmlNodeText(child, parts);
    }
    if (isBlock) appendBoundary(parts);
    return;
  }

  const text = (node as { toString?: () => string }).toString?.() ?? "";
  if (text.length > 0) parts.push(text);
}

function readXmlFragmentText(fragment: Y.XmlFragment): string {
  const parts: string[] = [];
  for (const node of fragment.toArray()) {
    readXmlNodeText(node, parts);
  }
  return parts
    .join("")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function readInitializedDocumentPreviewText(stateKey: string): {
  hasProseMirrorContent: boolean;
  initialized: boolean;
  text: string;
} {
  const state = getDocumentState(stateKey);
  const contentPreviewReady = Boolean(state?.initialized || state?._verifiedContentPreviewReady);
  if (!state || !contentPreviewReady) {
    return { hasProseMirrorContent: false, initialized: false, text: "" };
  }

  const sharedText = state.yDoc.getText("content").toString();
  if (sharedText.trim().length > 0) {
    return {
      hasProseMirrorContent: state.yDoc.getXmlFragment("prosemirror").length > 0,
      initialized: contentPreviewReady,
      text: sharedText,
    };
  }

  const sharedProseMirror = state.yDoc.getXmlFragment("prosemirror");
  return {
    hasProseMirrorContent: sharedProseMirror.length > 0,
    initialized: contentPreviewReady,
    text: readXmlFragmentText(sharedProseMirror),
  };
}
