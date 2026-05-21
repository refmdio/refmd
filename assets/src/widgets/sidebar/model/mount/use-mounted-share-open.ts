import { useNavigate } from "@solidjs/router";
import type {
  ShareMount,
  ShareMountDocument,
  ShareMountDetail,
  ShareTreeEntry,
} from "@/entities/mount";
import { currentWorkspaceId, setCurrentWorkspaceId } from "@/entities/workspace";
import { activateSharedDocumentRoute } from "@/features/editor";
import { createMountedShareDocumentPanelTarget, usePanelWorkspace } from "@/features/panel";
import {
  getShareMount,
  getShareMountDocumentByToken,
  getShareMountEntryDocument,
  openMountedShareDocument,
  respondShareMountPasswordChallenge,
} from "@/features/share";
import { Notice } from "@/shared/lib/notice";

export function useSidebarMountedShareOpen() {
  const navigate = useNavigate();
  const panelWorkspace = usePanelWorkspace();

  const openMountedDocumentPayload = async (
    mountId: string,
    detail: ShareMountDetail,
    document: ShareMountDocument,
    mode: "replace" | "tile",
  ) => {
    const opened = await openMountedShareDocument(mountId, detail, document);
    const isRootDocument = document.document_id === detail.mount.target_document_id;
    const target = createMountedShareDocumentPanelTarget({
      mountId,
      shareId: document.share_id,
      documentId: document.document_id,
      title: opened.title,
      workspaceId: document.workspace_id,
      routePath: isRootDocument
        ? `/mounts/${mountId}`
        : `/mounts/${mountId}?share=${document.share_id}`,
    });

    activateSharedDocumentRoute(target.targetKey, opened.access);

    if (currentWorkspaceId() !== detail.mount.workspace_id) {
      setCurrentWorkspaceId(detail.mount.workspace_id);
      await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
    }

    if (mode === "tile") {
      panelWorkspace.addToTile(target);
    } else {
      panelWorkspace.openDocument(target);
    }
  };

  const openMountedDocument = async (
    mount: ShareMount,
    mode: "replace" | "tile",
    shareId?: string | null,
    documentToken?: string | null,
  ) => {
    if (mount.status !== "active") {
      new Notice("This saved share is no longer available");
      return;
    }

    try {
      const loadDetail = async (allowPasswordBootstrap: boolean) =>
        shareId
          ? documentToken
            ? await getShareMountDocumentByToken(mount.id, documentToken)
            : await getShareMountEntryDocument(mount.id, shareId, { allowPasswordBootstrap })
          : await getShareMount(mount.id, { allowPasswordBootstrap });
      let detail: ShareMountDetail;
      try {
        detail = await loadDetail(false);
      } catch (err) {
        if (!mount.password_protected) throw err;
        try {
          await respondShareMountPasswordChallenge(mount.id);
          detail = await loadDetail(true);
        } catch {
          navigate(shareId ? `/mounts/${mount.id}?share=${shareId}` : `/mounts/${mount.id}`, {
            scroll: false,
          });
          return;
        }
      }
      if (!detail.document) {
        if (detail.mount.password_protected) {
          navigate(shareId ? `/mounts/${mount.id}?share=${shareId}` : `/mounts/${mount.id}`, {
            scroll: false,
          });
          return;
        }
        new Notice("This saved share cannot be opened.");
        return;
      }

      await openMountedDocumentPayload(mount.id, detail, detail.document, mode);
    } catch {
      new Notice("Saved share not found or access denied.");
    }
  };

  const openMount = (mount: ShareMount, toggleMount: (mount: ShareMount) => void) => {
    if (mount.status !== "active") {
      new Notice("This saved share is no longer available");
      return;
    }
    if (mount.target_kind === "folder") {
      toggleMount(mount);
      return;
    }
    void openMountedDocument(mount, "replace");
  };

  const addMountToTile = (mount: ShareMount) => {
    if (mount.target_kind === "folder") return;
    void openMountedDocument(mount, "tile");
  };

  const openMountEntry = (
    mount: ShareMount,
    entry: ShareTreeEntry,
    toggleMountEntry: (mount: ShareMount, entry: ShareTreeEntry) => void,
  ) => {
    if (entry.doc_type === "folder") {
      toggleMountEntry(mount, entry);
      return;
    }
    void openMountedDocument(mount, "replace", entry.share_id, entry.document_token);
  };

  const addMountEntryToTile = (mount: ShareMount, entry: ShareTreeEntry) => {
    if (entry.doc_type === "folder") return;
    void openMountedDocument(mount, "tile", entry.share_id, entry.document_token);
  };

  return {
    openMount,
    addMountToTile,
    openMountEntry,
    addMountEntryToTile,
  };
}
