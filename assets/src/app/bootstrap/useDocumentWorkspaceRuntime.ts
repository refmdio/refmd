import { onCleanup } from "solid-js";
import { useNavigate } from "@solidjs/router";
import type { QueryClient } from "@tanstack/solid-query";
import { attachActiveLeafRouteSync, usePanelWorkspace } from "@/features/panel";
import {
  setupFlushHooks,
  setFocusedPanelIdAccessor,
  setOnEditorRegistered,
} from "@/features/editor";
import { documentEvents } from "@/app/bootstrap/document-manager";
import type { App } from "@/shared/lib/workspace/app";
import { initializeDocumentRuntime } from "@/app/bootstrap/document-runtime";
import { initializeWorkspaceRuntime } from "@/app/bootstrap/workspace-runtime";

type DocumentWorkspace = ReturnType<typeof usePanelWorkspace>;
type Navigate = ReturnType<typeof useNavigate>;

export function useDocumentWorkspaceRuntime(
  documentWorkspace: DocumentWorkspace,
  navigate: Navigate,
  queryClient: QueryClient,
): App {
  setFocusedPanelIdAccessor(() => documentWorkspace.focusedPanelId());
  setOnEditorRegistered(() => documentEvents.flushPendingOpens());
  initializeDocumentRuntime(documentWorkspace, navigate, queryClient);
  const app = initializeWorkspaceRuntime(documentWorkspace);
  onCleanup(setupFlushHooks());

  onCleanup(attachActiveLeafRouteSync(navigate, () => documentWorkspace.openDocuments()));

  return app;
}
