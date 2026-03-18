import type { App } from "@/shared/lib/app-context";
import type { WorkspaceLeaf } from "@/shared/lib/view";
import { DocumentTreeView } from "./DocumentTreeView";

let currentApp: App | null = null;

export function loadDocumentTree(app: App): void {
  currentApp = app;
  app.workspace.registerView("document-tree", (leaf: WorkspaceLeaf) => new DocumentTreeView(leaf));
  app.workspace.addSidebarPanel({
    id: "document-tree",
    viewType: "document-tree",
    icon: "folder-tree",
    title: "Document Tree",
  });
}

export function unloadDocumentTree(): void {
  if (!currentApp) return;
  currentApp.workspace.removeSidebarPanel("document-tree");
  currentApp.workspace.unregisterView("document-tree");
  currentApp = null;
}
