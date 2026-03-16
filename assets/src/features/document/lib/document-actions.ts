import { documentsApi } from "@/shared/api";

export async function archiveDocument(documentId: string): Promise<void> {
  await documentsApi.archive(documentId);
}

export async function unarchiveDocument(documentId: string): Promise<void> {
  await documentsApi.unarchive(documentId);
}

export async function deleteDocument(documentId: string): Promise<void> {
  await documentsApi.delete(documentId);
}
