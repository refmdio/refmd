import { createEffect, createSignal, untrack } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import { setSelectedDocumentId, useDocuments } from "@/entities/document";
import { authState, cryptoWorkerReady } from "@/entities/session";
import { currentWorkspaceId, setCurrentWorkspaceId } from "@/entities/workspace";
import {
  isDocumentAccessError,
  resolveDocumentWithOfflineFallback,
  type ResolvedDocument,
} from "@/features/document";
import { usePanelWorkspace } from "@/features/panel";
import { Notice } from "@/shared/lib/notice";
import { DashboardWorkspace } from "./DashboardWorkspace";

export function DocumentWorkspaceRouteSync() {
  const navigate = useNavigate();
  const params = useParams<{ documentId?: string }>();
  const documentWorkspace = usePanelWorkspace();
  const { flatDocuments } = useDocuments(() => currentWorkspaceId());
  const [pendingRouteOpen, setPendingRouteOpen] = createSignal<ResolvedDocument | null>(null);
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

    if (!auth || !workerReady) return;

    if (focusedDocId === routeDocId && openDocs.has(routeDocId) && currentWorkspaceId()) {
      setPendingRouteOpen(null);
      return;
    }

    if (pending?.documentId === routeDocId) {
      if (!currentWorkspaceId()) {
        setCurrentWorkspaceId(pending.workspaceId);
      }
      return;
    }

    if (openDocs.has(routeDocId)) {
      const workspaceId = currentWorkspaceId();
      if (workspaceId) {
        setPendingRouteOpen({
          documentId: routeDocId,
          workspaceId,
          title: openDocs.get(routeDocId)?.title,
        });
        return;
      }
    }

    const localDoc = flatDocuments().find((candidate) => candidate.id === routeDocId);
    if (localDoc) {
      if (localDoc.doc_type !== "document") {
        new Notice("Folders cannot be opened in the editor.");
        navigate("/dashboard", { replace: true, scroll: false });
        return;
      }
      setPendingRouteOpen({
        documentId: localDoc.id,
        workspaceId: localDoc.workspace_id,
        title: localDoc.title,
      });
      return;
    }

    const requestVersion = ++routeRequestVersion;
    setPendingRouteOpen(null);

    void (async () => {
      try {
        const resolved = await resolveDocumentWithOfflineFallback(routeDocId);

        if (requestVersion !== routeRequestVersion || routeDocumentId() !== routeDocId) return;

        if (!resolved) {
          new Notice("Folders cannot be opened in the editor.");
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
        new Notice(
          isDocumentAccessError(error)
            ? "Document not found or access denied."
            : "Failed to open document.",
        );
        navigate("/dashboard", { replace: true, scroll: false });
      }
    })();
  });

  createEffect(() => {
    const pending = pendingRouteOpen();
    const workspaceId = currentWorkspaceId();
    if (!pending) return;
    if (!workspaceId) {
      setCurrentWorkspaceId(pending.workspaceId);
      return;
    }
    if (workspaceId !== pending.workspaceId) return;

    documentWorkspace.openDocument({
      id: pending.documentId,
      title: pending.title,
      workspaceId: pending.workspaceId,
    });
    setSelectedDocumentId(pending.documentId);
  });

  createEffect(() => {
    const pending = pendingRouteOpen();
    const focusedDocId = documentWorkspace.focusedDocumentId();
    if (!pending || focusedDocId !== pending.documentId) return;

    setPendingRouteOpen(null);
  });

  return <DashboardWorkspace />;
}
