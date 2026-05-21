import type { EventRef } from "@/shared/lib/events";
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
  let hasSeenDocumentPanel = false;
  const ref: EventRef = workspaceManager.on("active-leaf-change", (leaf) => {
    const panel = leaf ? decodePanelId(leaf.id) : null;
    if (panel) {
      hasSeenDocumentPanel = true;
    }
    if (!panel) {
      if (getOpenDocuments().size > 0) return;
      const pathname = window.location.pathname;
      const routeIsOwnedByDocumentWorkspace =
        pathname === getEmptyPath() ||
        pathname.startsWith("/document/") ||
        pathname.startsWith("/mounts/");
      if (!routeIsOwnedByDocumentWorkspace) return;
      if (pathname.startsWith("/document/") && !hasSeenDocumentPanel) return;
      if (pathname.startsWith("/mounts/") && !hasSeenDocumentPanel) return;
      const nextPath = getEmptyPath();
      if (pathname === nextPath) return;
      navigate(nextPath, { replace: true, scroll: false });
      return;
    }

    const nextPath =
      getOpenDocuments().get(panel.targetKey)?.routePath ?? `/document/${panel.documentId}`;
    if (window.location.pathname === nextPath) return;
    navigate(nextPath, { replace: true, scroll: false });
  });

  return () => workspaceManager.offref(ref);
}
