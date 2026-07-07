import { createSignal, onCleanup, type Accessor } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import type { DocumentResponse } from "@/entities/document";
import type { ShareMount } from "@/entities/mount";
import { moveDocument } from "@/features/document";
import { moveShareMount } from "@/features/share";
import { buildSidebarDragSiblings } from "./drag-siblings";

type DropPosition = "before" | "inside" | "after";

export interface SidebarDragTarget {
  id: string;
  kind: "document" | "folder" | "mount";
  parentId: string | null;
  archivedAt?: string | null;
}

export interface SidebarDropTarget {
  itemId: string;
  position: DropPosition;
}

function installSidebarDndListeners(
  draggedId: Accessor<string | null>,
  flatDocuments: Accessor<DocumentResponse[]>,
  onExternalDocumentDrop: ((docId: string) => void) | undefined,
  finishExternalDrop: () => void,
) {
  if (!onExternalDocumentDrop) return null;
  const handleDragOver = (e: DragEvent) => {
    const dragId = draggedId();
    if (!dragId || !flatDocuments().some((doc) => doc.id === dragId)) return;
    const target = e.target;
    if (target instanceof HTMLElement && target.closest("aside")) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
  };
  const handleDrop = (e: DragEvent) => {
    const dragId = draggedId();
    if (!dragId || !flatDocuments().some((doc) => doc.id === dragId)) return;
    const target = e.target;
    if (target instanceof HTMLElement && target.closest("aside")) return;
    e.preventDefault();
    e.stopPropagation();
    onExternalDocumentDrop(dragId);
    finishExternalDrop();
  };
  document.addEventListener("dragover", handleDragOver, { capture: true });
  document.addEventListener("drop", handleDrop, { capture: true });
  return () => {
    document.removeEventListener("dragover", handleDragOver, { capture: true });
    document.removeEventListener("drop", handleDrop, { capture: true });
  };
}

export function useSidebarTreeDrag(options: {
  workspaceId: Accessor<string | null | undefined>;
  flatDocuments: Accessor<DocumentResponse[]>;
  shareMounts: Accessor<ShareMount[]>;
  expand: (folderId: string) => void;
  onExternalDocumentDrop?: (docId: string) => void;
  onDragDropError?: (error: unknown) => void;
}) {
  const queryClient = useQueryClient();
  const [draggedId, setDraggedId] = createSignal<string | null>(null);
  const [dropTarget, setDropTarget] = createSignal<SidebarDropTarget | null>(null);
  let autoExpandTimer: ReturnType<typeof setTimeout> | null = null;
  let autoExpandTargetId: string | null = null;
  let cleanupDndListeners: (() => void) | null = null;

  onCleanup(() => {
    if (autoExpandTimer) clearTimeout(autoExpandTimer);
    cleanupDndListeners?.();
  });

  function isDescendant(parentId: string, childId: string): boolean {
    const docs = options.flatDocuments();
    let current = docs.find((doc) => doc.id === childId);
    while (current) {
      if (current.parent_id === parentId) return true;
      if (!current.parent_id) return false;
      current = docs.find((doc) => doc.id === current!.parent_id);
    }
    return false;
  }

  function canDrop(dragId: string, target: SidebarDragTarget, pos: DropPosition): boolean {
    if (dragId === target.id) return false;
    if (target.archivedAt) return false;
    if (pos === "inside" && target.kind !== "folder") return false;
    const draggedDocument = options.flatDocuments().find((doc) => doc.id === dragId);
    if (draggedDocument && pos === "inside" && isDescendant(dragId, target.id)) return false;
    const parentId = pos === "inside" ? target.id : target.parentId;
    if (draggedDocument && parentId) {
      if (parentId === dragId) return false;
      const parentDoc = options.flatDocuments().find((doc) => doc.id === parentId);
      if (parentDoc?.archived_at) return false;
      if (isDescendant(dragId, parentId)) return false;
    }
    return true;
  }

  function handleDragStart(e: DragEvent, itemId: string) {
    if (!e.dataTransfer) return;
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", itemId);
    setDraggedId(itemId);
    cleanupDndListeners?.();
    cleanupDndListeners = installSidebarDndListeners(
      draggedId,
      options.flatDocuments,
      options.onExternalDocumentDrop,
      () => {
        cleanupDndListeners?.();
        cleanupDndListeners = null;
        reset();
      },
    );
  }

  function handleDragOver(e: DragEvent, target: SidebarDragTarget, element: HTMLElement) {
    e.preventDefault();
    if (!e.dataTransfer) return;
    const dragId = draggedId();
    if (!dragId) return;
    const rect = element.getBoundingClientRect();
    const y = e.clientY - rect.top;
    const height = rect.height;
    let pos: DropPosition;
    if (target.kind === "folder") {
      if (y < height * 0.25) pos = "before";
      else if (y > height * 0.75) pos = "after";
      else pos = "inside";
    } else {
      pos = y < height * 0.5 ? "before" : "after";
    }
    if (!canDrop(dragId, target, pos)) {
      e.dataTransfer.dropEffect = "none";
      setDropTarget(null);
      clearAutoExpand();
      return;
    }
    e.dataTransfer.dropEffect = "move";
    setDropTarget({ itemId: target.id, position: pos });
    if (target.kind === "folder") startAutoExpand(target.id);
    else clearAutoExpand();
  }

  function handleDragLeave() {
    setDropTarget(null);
    clearAutoExpand();
  }

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    const target = dropTarget();
    const dragId = draggedId();
    if (!target || !dragId) {
      reset();
      return;
    }
    const targetDoc = options.flatDocuments().find((doc) => doc.id === target.itemId);
    const targetMount = options.shareMounts().find((mount) => mount.id === target.itemId);
    let parentId: string | null;
    let position: number;
    if (target.position === "inside") {
      parentId = target.itemId;
      position = getOrderedSiblings(parentId, dragId).length;
    } else {
      parentId = targetDoc?.parent_id ?? targetMount?.parent_id ?? null;
      const siblings = getOrderedSiblings(parentId, dragId);
      const targetIndex = siblings.findIndex((sibling) => sibling.key === target.itemId);
      position =
        target.position === "before"
          ? targetIndex >= 0
            ? targetIndex
            : 0
          : targetIndex >= 0
            ? targetIndex + 1
            : siblings.length;
    }
    void moveDraggedItem(dragId, parentId, position);
    reset();
  }

  function handleDragEnd() {
    cleanupDndListeners?.();
    cleanupDndListeners = null;
    reset();
  }

  function handleRootDragOver(e: DragEvent) {
    e.preventDefault();
    const dragId = draggedId();
    if (!dragId) return;
    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
    setDropTarget({ itemId: "__root__", position: "inside" });
    clearAutoExpand();
  }

  function handleRootDrop(e: DragEvent) {
    e.preventDefault();
    const dragId = draggedId();
    if (!dragId) {
      reset();
      return;
    }
    const position = getOrderedSiblings(null, dragId).length;
    void moveDraggedItem(dragId, null, position);
    reset();
  }

  async function moveDraggedItem(itemId: string, parentId: string | null, position: number) {
    try {
      const workspaceId = options.workspaceId();
      if (!workspaceId) return;
      if (options.flatDocuments().some((doc) => doc.id === itemId)) {
        await moveDocument(itemId, workspaceId, parentId, position);
        void queryClient.invalidateQueries({ queryKey: ["documents", workspaceId] });
      } else if (options.shareMounts().some((mount) => mount.id === itemId)) {
        await moveShareMount(itemId, { parentId, position });
        void queryClient.invalidateQueries({ queryKey: ["share-mounts", workspaceId] });
        void queryClient.invalidateQueries({ queryKey: ["documents", workspaceId] });
      }
      if (parentId) options.expand(parentId);
    } catch (error) {
      options.onDragDropError?.(error);
      if (!options.onDragDropError) throw error;
    }
  }

  function getOrderedSiblings(parentId: string | null, excludedItemId: string) {
    return buildSidebarDragSiblings(
      options.flatDocuments(),
      options.shareMounts(),
      parentId,
      excludedItemId,
    );
  }

  function startAutoExpand(folderId: string) {
    if (autoExpandTargetId === folderId) return;
    clearAutoExpand();
    autoExpandTargetId = folderId;
    autoExpandTimer = setTimeout(() => {
      options.expand(folderId);
      autoExpandTargetId = null;
    }, 500);
  }

  function clearAutoExpand() {
    if (autoExpandTimer) {
      clearTimeout(autoExpandTimer);
      autoExpandTimer = null;
    }
    autoExpandTargetId = null;
  }

  function reset() {
    setDraggedId(null);
    setDropTarget(null);
    clearAutoExpand();
  }

  return {
    draggedId,
    dropTarget,
    handleDragStart,
    handleDragOver,
    handleDragLeave,
    handleDrop,
    handleDragEnd,
    handleRootDragOver,
    handleRootDrop,
  };
}
