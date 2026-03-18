import type { App } from "@/shared/lib/app-context";
import type { EventRef } from "@/shared/lib/events";

let currentApp: App | null = null;
let statusBarEl: HTMLElement | null = null;
let wsRefs: EventRef[] = [];
let docRefs: EventRef[] = [];

function updateCount(): void {
  if (!statusBarEl || !currentApp) return;
  const doc = currentApp.documents.getActiveDocument();
  if (!doc) {
    statusBarEl.textContent = "";
    return;
  }
  const text = doc.editor.getValue();
  const words = text.split(/\s+/).filter(Boolean).length;
  const chars = text.length;
  statusBarEl.textContent = `${words} words, ${chars} chars`;
}

export function loadWordCount(app: App): void {
  currentApp = app;
  statusBarEl = app.workspace.addStatusBarItem();

  wsRefs = [
    app.workspace.on("editor-change", updateCount),
    app.workspace.on("active-leaf-change", updateCount),
  ];
  docRefs = [app.documents.on("document-open", updateCount)];

  updateCount();
}

export function unloadWordCount(): void {
  if (!currentApp) return;
  for (const ref of wsRefs) {
    currentApp.workspace.offref(ref);
  }
  for (const ref of docRefs) {
    currentApp.documents.offref(ref);
  }
  wsRefs = [];
  docRefs = [];
  statusBarEl?.remove();
  statusBarEl = null;
  currentApp = null;
}
