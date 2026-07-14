import * as Y from "yjs";

const CANONICAL_TEXT_FIELD = "content";

export function canonicalMarkdownText(doc: Y.Doc): string {
  return doc.getText(CANONICAL_TEXT_FIELD).toJSON();
}

function encodeEmptyUpdate(): Uint8Array {
  const emptyDoc = new Y.Doc();
  try {
    return Y.encodeStateAsUpdate(emptyDoc);
  } finally {
    emptyDoc.destroy();
  }
}

export function replaceYTextWithMinimalDiff(text: Y.Text, next: string): void {
  const current = text.toJSON();
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

export function clearProseMirrorXml(doc: Y.Doc, origin: unknown = "remote"): void {
  const proseMirrorXml = doc.getXmlFragment("prosemirror");
  if (proseMirrorXml.length === 0) return;
  doc.transact(() => {
    proseMirrorXml.delete(0, proseMirrorXml.length);
  }, origin);
}

export function encodeCanonicalSyncedStateAsUpdate(doc: Y.Doc): Uint8Array {
  const syncedDoc = new Y.Doc();
  try {
    Y.applyUpdate(syncedDoc, Y.encodeStateAsUpdate(doc), "remote");
    clearProseMirrorXml(syncedDoc, "canonical-synced-state");
    return Y.encodeStateAsUpdate(syncedDoc);
  } finally {
    syncedDoc.destroy();
  }
}

function withCanonicalSyncedDoc<T>(doc: Y.Doc, fn: (canonicalDoc: Y.Doc) => T): T {
  const syncedDoc = new Y.Doc();
  try {
    Y.applyUpdate(syncedDoc, Y.encodeStateAsUpdate(doc), "remote");
    clearProseMirrorXml(syncedDoc, "canonical-synced-state");
    return fn(syncedDoc);
  } finally {
    syncedDoc.destroy();
  }
}

export function encodeCanonicalStateAsUpdate(doc: Y.Doc): Uint8Array {
  return withCanonicalSyncedDoc(doc, (canonicalDoc) => Y.encodeStateAsUpdate(canonicalDoc));
}

export function encodeCanonicalStateAsUpdateV2(doc: Y.Doc): Uint8Array {
  return withCanonicalSyncedDoc(doc, (canonicalDoc) => Y.encodeStateAsUpdateV2(canonicalDoc));
}

export function encodeCanonicalStateVector(doc: Y.Doc): Uint8Array {
  return withCanonicalSyncedDoc(doc, (canonicalDoc) => Y.encodeStateVector(canonicalDoc));
}

function tryEncodeLiveCanonicalDiff(
  doc: Y.Doc,
  confirmedState: Uint8Array,
  beforeVector: Uint8Array,
  nextText: string,
): Uint8Array | null {
  const liveDoc = new Y.Doc();
  const validationDoc = new Y.Doc();
  try {
    Y.applyUpdate(liveDoc, Y.encodeStateAsUpdate(doc), "remote");
    clearProseMirrorXml(liveDoc, "canonical-live-diff");
    const candidate = Y.encodeStateAsUpdate(liveDoc, beforeVector);
    if (
      doc.getXmlFragment("prosemirror").length > 0 &&
      candidate.length > Math.max(4096, nextText.length * 4 + 1024)
    ) {
      return null;
    }

    Y.applyUpdate(validationDoc, confirmedState, "remote");
    Y.applyUpdate(validationDoc, candidate, "remote");
    return canonicalMarkdownText(validationDoc) === nextText ? candidate : null;
  } finally {
    liveDoc.destroy();
    validationDoc.destroy();
  }
}

export function encodeCanonicalDiffAsUpdate(
  doc: Y.Doc,
  confirmedState: Uint8Array | null,
): Uint8Array | null {
  if (!confirmedState) return encodeCanonicalStateAsUpdate(doc);

  const nextText = canonicalMarkdownText(doc);
  const confirmedDoc = new Y.Doc();
  try {
    Y.applyUpdate(confirmedDoc, confirmedState, "remote");
    if (canonicalMarkdownText(confirmedDoc) === nextText) return encodeEmptyUpdate();

    const beforeVector = Y.encodeStateVector(confirmedDoc);
    const liveDiff = tryEncodeLiveCanonicalDiff(doc, confirmedState, beforeVector, nextText);
    if (liveDiff) return liveDiff;
    return null;
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

export function replaceDocWithCanonicalText(
  targetDoc: Y.Doc,
  text: string,
  origin: unknown = "remote",
): void {
  const targetText = targetDoc.getText(CANONICAL_TEXT_FIELD);
  const proseMirrorXml = targetDoc.getXmlFragment("prosemirror");
  targetDoc.transact(() => {
    replaceYTextWithMinimalDiff(targetText, text);
    if (proseMirrorXml.length > 0) proseMirrorXml.delete(0, proseMirrorXml.length);
  }, origin);
}

export function applyAuthoritativeCanonicalState(
  targetDoc: Y.Doc,
  sourceDoc: Y.Doc,
  origin: unknown = "remote",
): void {
  const expectedText = canonicalMarkdownText(sourceDoc);
  Y.applyUpdate(targetDoc, encodeCanonicalSyncedStateAsUpdate(sourceDoc), origin);
  clearProseMirrorXml(targetDoc, origin);

  if (canonicalMarkdownText(targetDoc) !== expectedText) {
    replaceDocWithCanonicalText(targetDoc, expectedText, origin);
  }

  if (canonicalMarkdownText(targetDoc) !== expectedText) {
    throw new Error("canonical_state_reconstruction_failed");
  }
}

export function replaceDocWithCanonicalMarkdown(
  targetDoc: Y.Doc,
  sourceDoc: Y.Doc,
  origin: unknown = "remote",
): void {
  replaceDocWithCanonicalText(targetDoc, canonicalMarkdownText(sourceDoc), origin);
}
