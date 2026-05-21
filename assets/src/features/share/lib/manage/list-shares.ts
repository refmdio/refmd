import { sharesApi, type components } from "@/shared/api";

export type ShareListItem = components["schemas"]["ShareListItem"];

export async function listDocumentShares(documentId: string): Promise<ShareListItem[]> {
  const response = await sharesApi.listDocumentShares(documentId);
  return response.shares;
}
