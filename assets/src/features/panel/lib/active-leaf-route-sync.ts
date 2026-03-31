import type { EventRef } from "@/shared/lib/events";
import { buildDocumentPath } from "@/shared/lib/document-routes";
import { decodePanelId } from "./panel-utils";
import { workspaceManager } from "./workspace-manager";

interface NavigateOptions {
  replace?: boolean;
  scroll?: boolean;
}

type NavigateFn = (path: string, options?: NavigateOptions) => void;

export function attachActiveLeafRouteSync(
  navigate: NavigateFn,
  getOpenDocuments: () => Map<string, { title?: string }>,
): () => void {
  const ref: EventRef = workspaceManager.on("active-leaf-change", (leaf) => {
    const panel = leaf ? decodePanelId(leaf.id) : null;
    if (!panel) {
      if (getOpenDocuments().size > 0) return;
      const nextPath = buildDocumentPath(null);
      if (window.location.pathname === nextPath) return;
      navigate(nextPath, { replace: true, scroll: false });
      return;
    }

    const nextPath = buildDocumentPath(panel.documentId);
    if (window.location.pathname === nextPath) return;
    navigate(nextPath, { replace: true, scroll: false });
  });

  return () => workspaceManager.offref(ref);
}
