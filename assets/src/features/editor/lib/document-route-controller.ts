import { createEffect, createSignal, untrack } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import { setSelectedDocumentId } from "@/entities/document";
import { currentWorkspaceId, setCurrentWorkspaceId } from "@/entities/workspace";
import { ApiError, documentsApi } from "@/shared/api";
import { authState, cryptoWorkerReady } from "@/shared/lib/auth-state";
import {
  getDocumentCache,
  getOfflineCreated,
  getOfflineDocumentMeta,
} from "@/shared/lib/offline/offline-store";
import { Notice } from "@/shared/lib/notice";

interface PendingRouteOpen {
  documentId: string;
  workspaceId: string;
  title?: string;
}

interface DocumentRouteWorkspace {
  focusedDocumentId: () => string | null;
  openDocuments: () => Map<string, { title?: string }>;
  openDocument: (doc: { id: string; title?: string }) => void;
}

async function resolveRouteDocument(documentId: string): Promise<PendingRouteOpen | null> {
  const document = await documentsApi.get(documentId);
  if (document.doc_type !== "document") return null;

  return {
    documentId: document.id,
    workspaceId: document.workspace_id,
    title: document.title,
  };
}

async function resolveOfflineRouteDocument(documentId: string): Promise<PendingRouteOpen | null> {
  const [offlineMeta, cacheEntry, offlineCreated] = await Promise.all([
    getOfflineDocumentMeta(documentId).catch(() => null),
    getDocumentCache(documentId).catch(() => null),
    getOfflineCreated(documentId).catch(() => null),
  ]);

  const workspaceId =
    offlineMeta?.workspaceId ?? cacheEntry?.workspaceId ?? offlineCreated?.workspaceId ?? null;

  if (!workspaceId) return null;

  return {
    documentId,
    workspaceId,
  };
}

export function useDocumentRouteController(documentWorkspace: DocumentRouteWorkspace): void {
  const navigate = useNavigate();
  const params = useParams<{ documentId?: string }>();
  const [pendingRouteOpen, setPendingRouteOpen] = createSignal<PendingRouteOpen | null>(null);
  let routeRequestVersion = 0;

  const routeDocumentId = () => {
    const id = params.documentId;
    return typeof id === "string" && id.length > 0 ? id : null;
  };

  createEffect(() => {
    const routeDocId = routeDocumentId();
    const auth = authState();
    const workerReady = cryptoWorkerReady();
    const focusedDocId = untrack(() => documentWorkspace.focusedDocumentId());
    const openDocs = untrack(() => documentWorkspace.openDocuments());
    const pending = untrack(() => pendingRouteOpen());

    if (!routeDocId) {
      routeRequestVersion += 1;
      setPendingRouteOpen(null);
      return;
    }

    if (!auth || !workerReady) {
      return;
    }

    if (focusedDocId === routeDocId && openDocs.has(routeDocId)) {
      setPendingRouteOpen(null);
      return;
    }

    if (pending?.documentId === routeDocId) {
      return;
    }

    if (openDocs.has(routeDocId)) {
      const workspaceId = currentWorkspaceId();
      if (!workspaceId) return;

      setPendingRouteOpen({
        documentId: routeDocId,
        workspaceId,
        title: openDocs.get(routeDocId)?.title,
      });
      return;
    }

    const requestVersion = ++routeRequestVersion;
    setPendingRouteOpen(null);

    void (async () => {
      try {
        const resolved =
          (await resolveRouteDocument(routeDocId).catch(async (error) => {
            const offline = await resolveOfflineRouteDocument(routeDocId);
            if (offline) return offline;
            throw error;
          })) ?? null;

        if (requestVersion !== routeRequestVersion || routeDocumentId() !== routeDocId) return;

        if (!resolved) {
          new Notice("Folders cannot be opened in the editor.");
          setPendingRouteOpen(null);
          navigate("/dashboard", { replace: true, scroll: false });
          return;
        }

        setPendingRouteOpen(resolved);
        if (currentWorkspaceId() !== resolved.workspaceId) {
          setCurrentWorkspaceId(resolved.workspaceId);
        }
      } catch (error) {
        if (requestVersion !== routeRequestVersion || routeDocumentId() !== routeDocId) return;

        setPendingRouteOpen(null);

        if (error instanceof ApiError && (error.status === 403 || error.status === 404)) {
          new Notice("Document not found or access denied.");
        } else {
          new Notice("Failed to open document.");
        }

        navigate("/dashboard", { replace: true, scroll: false });
      }
    })();
  });

  createEffect(() => {
    const pending = pendingRouteOpen();
    const workspaceId = currentWorkspaceId();
    if (!pending || !workspaceId || workspaceId !== pending.workspaceId) return;

    documentWorkspace.openDocument({ id: pending.documentId, title: pending.title });
    setSelectedDocumentId(pending.documentId);
  });

  createEffect(() => {
    const pending = pendingRouteOpen();
    const focusedDocId = documentWorkspace.focusedDocumentId();
    if (!pending || focusedDocId !== pending.documentId) return;

    setPendingRouteOpen(null);
  });
}
