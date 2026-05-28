import type { EventRef } from "@/shared/lib/events";
import type { WorkspaceLeaf } from "@/shared/lib/workspace/view";
import { decodePanelId } from "../workspace/panel-utils";
import { workspaceManager } from "./workspace-manager";

interface NavigateOptions {
  replace?: boolean;
  scroll?: boolean;
}

type NavigateFn = (path: string, options?: NavigateOptions) => void;

export function attachActiveLeafRouteSync(
  navigate: NavigateFn,
  getOpenDocuments: () => Map<string, { routePath: string }>,
  getEmptyPath: () => string = () => "/dashboard",
): () => void {
  let hasSeenWorkspaceTile = false;
  const syncRouteForLeaf = (leaf: WorkspaceLeaf | null) => {
    const panel = leaf ? decodePanelId(leaf.id) : null;
    if (panel) {
      hasSeenWorkspaceTile = true;
    }
    if (!panel) {
      if (getOpenDocuments().size > 0) return;
      const pathname = window.location.pathname;
      const routeIsOwnedByDocumentWorkspace =
        pathname === getEmptyPath() ||
        pathname.startsWith("/document/") ||
        pathname.startsWith("/mounts/");
      if (!routeIsOwnedByDocumentWorkspace) return;
      if (pathname.startsWith("/document/") && !hasSeenWorkspaceTile) return;
      if (pathname.startsWith("/mounts/") && !hasSeenWorkspaceTile) return;
      const nextPath = getEmptyPath();
      if (pathname === nextPath) return;
      navigate(nextPath, { replace: true, scroll: false });
      return;
    }

    const nextPath =
      getOpenDocuments().get(panel.targetKey)?.routePath ?? `/document/${panel.documentId}`;
    if (window.location.pathname === nextPath) return;
    navigate(nextPath, { replace: true, scroll: false });
  };

  const ref: EventRef = workspaceManager.on("active-leaf-change", syncRouteForLeaf);
  syncRouteForLeaf(workspaceManager.getActiveLeaf());

  return () => workspaceManager.offref(ref);
}
