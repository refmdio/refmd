import { documentsApi } from "@/shared/api";
import { getApp } from "@/shared/lib/app-context";

export async function archiveDocument(documentId: string): Promise<void> {
  await documentsApi.archive(documentId);
}

export async function unarchiveDocument(documentId: string): Promise<void> {
  await documentsApi.unarchive(documentId);
}

export async function deleteDocument(documentId: string): Promise<void> {
  await documentsApi.delete(documentId);
  getApp().documentEvents.notifyDocumentDelete(documentId);
}
