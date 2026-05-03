import type { DragSibling, DocumentResponse } from "@/entities/document";
import type { ShareMount } from "@/entities/mount";

export function buildSidebarDragSiblings(
  documents: DocumentResponse[],
  mounts: ShareMount[],
  parentId: string | null,
  excludedDocumentId: string,
): DragSibling[] {
  return [
    ...documents
      .filter((doc) => (doc.parent_id ?? null) === parentId && doc.id !== excludedDocumentId)
      .map((doc) => ({
        key: doc.id,
        documentId: doc.id,
        position: doc.position,
      })),
    ...mounts
      .filter((mount) => (mount.parent_id ?? null) === parentId)
      .map((mount) => ({
        key: mount.id,
        position: mount.position,
      })),
  ].sort((a, b) => {
    const positionDiff = a.position - b.position;
    if (positionDiff !== 0) return positionDiff;
    return a.key.localeCompare(b.key);
  });
}
