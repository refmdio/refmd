import type { App } from "@/shared/lib/workspace/app";
import type { WorkspaceLeaf } from "@/shared/lib/workspace/view";
import { corePluginSurfaceOwner, type CorePluginLoadContext } from "@/features/plugin-runtime";
import { DocumentTreeView } from "./DocumentTreeView";

let currentApp: App | null = null;

export function loadDocumentTree(app: App, context: CorePluginLoadContext): void {
  currentApp = app;
  app.workspace.registerView("document-tree", (leaf: WorkspaceLeaf) => new DocumentTreeView(leaf));
  app.workspace.addSidebarPanel({
    id: "document-tree",
    owner: corePluginSurfaceOwner(context),
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
