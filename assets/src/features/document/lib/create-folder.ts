import { documentsApi } from "@/shared/api";

export async function createFolder(
  workspaceId: string,
  title: string,
  parentId: string | null,
): Promise<string> {
  const result = await documentsApi.create({
    workspace_id: workspaceId,
    doc_type: "folder",
    title,
    parent_id: parentId,
  });
  return result.id;
}
