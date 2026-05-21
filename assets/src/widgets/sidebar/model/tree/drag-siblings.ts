import type { DocumentResponse } from "@/entities/document";
import type { ShareMount } from "@/entities/mount";

export type SidebarDragSibling = {
  key: string;
  documentId?: string;
  mountId?: string;
  position: number;
};

export function buildSidebarDragSiblings(
  documents: DocumentResponse[],
  mounts: ShareMount[],
  parentId: string | null,
  excludedItemId: string,
): SidebarDragSibling[] {
  return [
    ...documents
      .filter((doc) => (doc.parent_id ?? null) === parentId && doc.id !== excludedItemId)
      .map((doc) => ({
        key: doc.id,
        documentId: doc.id,
        position: doc.position,
      })),
    ...mounts
      .filter((mount) => (mount.parent_id ?? null) === parentId && mount.id !== excludedItemId)
      .map((mount) => ({
        key: mount.id,
        mountId: mount.id,
        position: mount.position,
      })),
  ].sort((a, b) => {
    const positionDiff = a.position - b.position;
    if (positionDiff !== 0) return positionDiff;
    return a.key.localeCompare(b.key);
  });
}
