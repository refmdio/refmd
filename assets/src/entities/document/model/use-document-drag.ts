import { createSignal, onCleanup, type Accessor } from "solid-js";
import type { DocumentResponse } from "./types";
function installDocumentDndListeners(
  draggedId: Accessor<string | null>,
  onExternalDrop: ((docId: string) => void) | undefined,
  finishExternalDrop: () => void,
) {
  if (!onExternalDrop) return null;
  const handleDragOver = (e: DragEvent) => {
    if (!draggedId()) return;
    const target = e.target;
    if (target instanceof HTMLElement && target.closest("aside")) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
  };
  const handleDrop = (e: DragEvent) => {
    const currentDraggedId = draggedId();
    if (!currentDraggedId) return;
    const target = e.target;
    if (target instanceof HTMLElement && target.closest("aside")) return;
    e.preventDefault();
    e.stopPropagation();
    onExternalDrop(currentDraggedId);
    finishExternalDrop();
  };
  document.addEventListener("dragover", handleDragOver, { capture: true });
  document.addEventListener("drop", handleDrop, { capture: true });
  return () => {
    document.removeEventListener("dragover", handleDragOver, { capture: true });
    document.removeEventListener("drop", handleDrop, { capture: true });
  };
}
type DropPosition = "before" | "inside" | "after";
export interface DropTarget {
  documentId: string;
  position: DropPosition;
}
export function useDocumentDrag(
  flatDocuments: () => DocumentResponse[],
  onDrop: (draggedId: string, targetParentId: string | null, position: number) => void,
  expandFolder: (folderId: string) => void,
  onExternalDrop?: (docId: string) => void,
) {
  const [draggedId, setDraggedId] = createSignal<string | null>(null);
  const [dropTarget, setDropTarget] = createSignal<DropTarget | null>(null);
  let autoExpandTimer: ReturnType<typeof setTimeout> | null = null;
  let autoExpandTargetId: string | null = null;
  let cleanupDndListeners: (() => void) | null = null;
  onCleanup(() => {
    if (autoExpandTimer) clearTimeout(autoExpandTimer);
    cleanupDndListeners?.();
  });
  function isDescendant(parentId: string, childId: string): boolean {
    const docs = flatDocuments();
    let current = docs.find((d) => d.id === childId);
    while (current) {
      if (current.parent_id === parentId) return true;
      if (!current.parent_id) return false;
      current = docs.find((d) => d.id === current!.parent_id);
    }
    return false;
  }
  function canDrop(dragId: string, targetDoc: DocumentResponse, pos: DropPosition): boolean {
    if (dragId === targetDoc.id) return false;
    if (targetDoc.archived_at) return false;
    if (pos === "inside" && targetDoc.doc_type !== "folder") return false;
    if (pos === "inside" && isDescendant(dragId, targetDoc.id)) return false;
    const parentId = pos === "inside" ? targetDoc.id : (targetDoc.parent_id ?? null);
    if (parentId) {
      if (parentId === dragId) return false;
      const parentDoc = flatDocuments().find((d) => d.id === parentId);
      if (parentDoc?.archived_at) return false;
      if (isDescendant(dragId, parentId)) return false;
    }
    return true;
  }
  function handleDragStart(e: DragEvent, docId: string) {
    if (!e.dataTransfer) return;
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", docId);
    setDraggedId(docId);
    cleanupDndListeners?.();
    cleanupDndListeners = installDocumentDndListeners(draggedId, onExternalDrop, () => {
      cleanupDndListeners?.();
      cleanupDndListeners = null;
      reset();
    });
  }
  function handleDragOver(e: DragEvent, targetDoc: DocumentResponse, element: HTMLElement) {
    e.preventDefault();
    if (!e.dataTransfer) return;
    const dragId = draggedId();
    if (!dragId) return;
    const rect = element.getBoundingClientRect();
    const y = e.clientY - rect.top;
    const height = rect.height;
    let pos: DropPosition;
    if (targetDoc.doc_type === "folder") {
      if (y < height * 0.25) pos = "before";
      else if (y > height * 0.75) pos = "after";
      else pos = "inside";
    } else {
      pos = y < height * 0.5 ? "before" : "after";
    }
    if (!canDrop(dragId, targetDoc, pos)) {
      e.dataTransfer.dropEffect = "none";
      setDropTarget(null);
      clearAutoExpand();
      return;
    }
    e.dataTransfer.dropEffect = "move";
    setDropTarget({ documentId: targetDoc.id, position: pos });
    if (targetDoc.doc_type === "folder") {
      startAutoExpand(targetDoc.id);
    } else {
      clearAutoExpand();
    }
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
    const docs = flatDocuments();
    const targetDoc = docs.find((d) => d.id === target.documentId);
    if (!targetDoc) {
      reset();
      return;
    }
    let parentId: string | null;
    let position: number;
    if (target.position === "inside") {
      parentId = targetDoc.id;
      const siblings = docs.filter((d) => d.parent_id === parentId && d.id !== dragId);
      position = siblings.length;
    } else {
      parentId = targetDoc.parent_id ?? null;
      const siblings = docs
        .filter((d) => (d.parent_id ?? null) === parentId && d.id !== dragId)
        .sort((a, b) => a.position - b.position);
      const targetIndex = siblings.findIndex((d) => d.id === targetDoc.id);
      if (target.position === "before") {
        position = targetIndex >= 0 ? targetIndex : 0;
      } else {
        position = targetIndex >= 0 ? targetIndex + 1 : siblings.length;
      }
    }
    onDrop(dragId, parentId, position);
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
    setDropTarget({ documentId: "__root__", position: "inside" });
    clearAutoExpand();
  }
  function handleRootDrop(e: DragEvent) {
    e.preventDefault();
    const dragId = draggedId();
    if (!dragId) {
      reset();
      return;
    }
    const docs = flatDocuments();
    const siblings = docs.filter((d) => !d.parent_id && d.id !== dragId);
    onDrop(dragId, null, siblings.length);
    reset();
  }
  function startAutoExpand(folderId: string) {
    if (autoExpandTargetId === folderId) return;
    clearAutoExpand();
    autoExpandTargetId = folderId;
    autoExpandTimer = setTimeout(() => {
      expandFolder(folderId);
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
