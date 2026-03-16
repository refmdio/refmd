import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";

type ScrollListener = (ratio: number, sourceId: string) => void;

interface YDocEntry {
  yDoc: Y.Doc;
  awareness: Awareness;
  refCount: number;
}

const cache = new Map<string, YDocEntry>();
const scrollListeners = new Map<string, Set<ScrollListener>>();

export function acquireYDoc(documentId: string): { yDoc: Y.Doc; awareness: Awareness } {
  const existing = cache.get(documentId);
  if (existing) {
    existing.refCount++;
    return { yDoc: existing.yDoc, awareness: existing.awareness };
  }

  const yDoc = new Y.Doc();
  const awareness = new Awareness(yDoc);
  cache.set(documentId, { yDoc, awareness, refCount: 1 });
  return { yDoc, awareness };
}

export function releaseYDoc(documentId: string): void {
  const entry = cache.get(documentId);
  if (!entry) return;

  entry.refCount--;
  if (entry.refCount <= 0) {
    entry.awareness.destroy();
    entry.yDoc.destroy();
    cache.delete(documentId);
  }
}

export function onScrollSync(scrollGroupId: string, listener: ScrollListener): () => void {
  let set = scrollListeners.get(scrollGroupId);
  if (!set) {
    set = new Set();
    scrollListeners.set(scrollGroupId, set);
  }
  set.add(listener);
  return () => {
    set!.delete(listener);
    if (set!.size === 0) scrollListeners.delete(scrollGroupId);
  };
}

export function emitScrollSync(scrollGroupId: string, ratio: number, sourceId: string): void {
  const set = scrollListeners.get(scrollGroupId);
  if (!set) return;
  for (const listener of set) {
    listener(ratio, sourceId);
  }
}
