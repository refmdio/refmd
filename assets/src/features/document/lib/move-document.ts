import { documentsApi } from "@/shared/api";

export async function moveDocument(
  documentId: string,
  workspaceId: string,
  parentId: string | null,
  position: number,
): Promise<void> {
  await documentsApi.reorder({
    document_id: documentId,
    workspace_id: workspaceId,
    parent_id: parentId,
    position,
  });
}
