type ScrollListener = (ratio: number, sourceId: string) => void;

const scrollListeners = new Map<string, Set<ScrollListener>>();

export function onScrollSync(scrollGroupId: string, listener: ScrollListener): () => void {
  let listeners = scrollListeners.get(scrollGroupId);
  if (!listeners) {
    listeners = new Set();
    scrollListeners.set(scrollGroupId, listeners);
  }
  listeners.add(listener);
  return () => {
    listeners!.delete(listener);
    if (listeners!.size === 0) scrollListeners.delete(scrollGroupId);
  };
}

export function emitScrollSync(scrollGroupId: string, ratio: number, sourceId: string): void {
  const listeners = scrollListeners.get(scrollGroupId);
  if (!listeners) return;
  for (const listener of listeners) {
    listener(ratio, sourceId);
  }
}
