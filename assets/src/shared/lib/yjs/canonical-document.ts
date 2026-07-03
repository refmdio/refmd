import * as Y from "yjs";

const CANONICAL_TEXT_FIELD = "content";

export function canonicalMarkdownText(doc: Y.Doc): string {
  return doc.getText(CANONICAL_TEXT_FIELD).toString();
}

function createCanonicalDoc(doc: Y.Doc): Y.Doc {
  const canonicalDoc = new Y.Doc();
  const text = canonicalMarkdownText(doc);
  if (text.length > 0) {
    canonicalDoc.getText(CANONICAL_TEXT_FIELD).insert(0, text);
  }
  return canonicalDoc;
}

function withCanonicalDoc<T>(doc: Y.Doc, fn: (canonicalDoc: Y.Doc) => T): T {
  const canonicalDoc = createCanonicalDoc(doc);
  try {
    return fn(canonicalDoc);
  } finally {
    canonicalDoc.destroy();
  }
}

export function replaceYTextWithMinimalDiff(text: Y.Text, next: string): void {
  const current = text.toString();
  if (current === next) return;

  let start = 0;
  const minLength = Math.min(current.length, next.length);
  while (start < minLength && current.charCodeAt(start) === next.charCodeAt(start)) {
    start++;
  }

  let currentEnd = current.length;
  let nextEnd = next.length;
  while (
    currentEnd > start &&
    nextEnd > start &&
    current.charCodeAt(currentEnd - 1) === next.charCodeAt(nextEnd - 1)
  ) {
    currentEnd--;
    nextEnd--;
  }

  const deleteCount = currentEnd - start;
  const insertText = next.slice(start, nextEnd);
  if (deleteCount > 0) text.delete(start, deleteCount);
  if (insertText.length > 0) text.insert(start, insertText);
}

export function encodeCanonicalStateAsUpdate(doc: Y.Doc): Uint8Array {
  return withCanonicalDoc(doc, (canonicalDoc) => Y.encodeStateAsUpdate(canonicalDoc));
}

export function encodeCanonicalStateAsUpdateV2(doc: Y.Doc): Uint8Array {
  return withCanonicalDoc(doc, (canonicalDoc) => Y.encodeStateAsUpdateV2(canonicalDoc));
}

export function encodeCanonicalStateVector(doc: Y.Doc): Uint8Array {
  return withCanonicalDoc(doc, (canonicalDoc) => Y.encodeStateVector(canonicalDoc));
}

export function encodeCanonicalDiffAsUpdate(
  doc: Y.Doc,
  confirmedState: Uint8Array | null,
): Uint8Array {
  if (!confirmedState) return encodeCanonicalStateAsUpdate(doc);

  const nextText = canonicalMarkdownText(doc);
  const confirmedDoc = new Y.Doc();
  try {
    Y.applyUpdate(confirmedDoc, confirmedState, "remote");
    const beforeVector = Y.encodeStateVector(confirmedDoc);
    const confirmedText = confirmedDoc.getText(CANONICAL_TEXT_FIELD);
    confirmedDoc.transact(() => replaceYTextWithMinimalDiff(confirmedText, nextText), "local");
    return Y.encodeStateAsUpdate(confirmedDoc, beforeVector);
  } finally {
    confirmedDoc.destroy();
  }
}

export function encodeCanonicalStateFromAppliedUpdates(
  updates: readonly { update: Uint8Array; version: "v1" | "v2" }[],
): Uint8Array {
  const doc = new Y.Doc();
  try {
    for (const item of updates) {
      if (item.version === "v2") {
        Y.applyUpdateV2(doc, item.update, "remote");
      } else {
        Y.applyUpdate(doc, item.update, "remote");
      }
    }
    return encodeCanonicalStateAsUpdate(doc);
  } finally {
    doc.destroy();
  }
}

export function replaceDocWithCanonicalMarkdown(
  targetDoc: Y.Doc,
  sourceDoc: Y.Doc,
  origin: unknown = "remote",
): void {
  const text = canonicalMarkdownText(sourceDoc);
  const targetText = targetDoc.getText(CANONICAL_TEXT_FIELD);
  const proseMirrorXml = targetDoc.getXmlFragment("prosemirror");
  targetDoc.transact(() => {
    replaceYTextWithMinimalDiff(targetText, text);
    if (proseMirrorXml.length > 0) proseMirrorXml.delete(0, proseMirrorXml.length);
  }, origin);
}
