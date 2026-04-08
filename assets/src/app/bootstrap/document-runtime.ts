import type { QueryClient } from "@tanstack/solid-query";
import { currentWorkspaceId } from "@/entities/workspace";
import { createDocumentWithOfflineFallback } from "@/features/document";
import {
  acquireDocumentState,
  createDocumentOffline,
  getActiveEditor,
  getDocumentState,
  getDocText,
  getEditorForDocument,
  initializeDocumentSync,
  releaseDocumentState,
} from "@/features/editor";
import { documentNavigation } from "@/entities/document";
import { documentRuntime } from "@/app/bootstrap/document-manager";
import type { useNavigate } from "@solidjs/router";
import type { usePanelWorkspace } from "@/features/panel";

type DocumentWorkspace = ReturnType<typeof usePanelWorkspace>;
type EditorDocumentState = NonNullable<ReturnType<typeof getDocumentState>>;
type Navigate = ReturnType<typeof useNavigate>;

export function initializeDocumentRuntime(
  documentWorkspace: DocumentWorkspace,
  navigate: Navigate,
  queryClient: QueryClient,
): void {
  documentNavigation.init((documentId) =>
    navigate(documentId ? `/document/${documentId}` : "/dashboard", {
      replace: true,
      scroll: false,
    }),
  );

  documentRuntime.init(
    {
      focusedDocumentId: () => documentWorkspace.focusedDocumentId(),
    },
    queryClient,
    () => currentWorkspaceId(),
    () => getActiveEditor(),
    (docId) => getEditorForDocument(docId),
    {
      acquireDocumentState,
      getDocumentState,
      releaseDocumentState,
      initializeDocumentSync: (documentId, workspaceId, state) =>
        initializeDocumentSync(documentId, workspaceId, state as EditorDocumentState),
    },
  );
  documentRuntime.setDocTextResolver((id) => getDocText(id));
  documentRuntime.setOpenDocumentFn((documentId) => {
    documentNavigation.openDocument(documentId);
  });
  documentRuntime.setCreateDocumentFn(async (wsId, title, parentId) => {
    return createDocumentWithOfflineFallback(createDocumentOffline, wsId, title, parentId);
  });
}
