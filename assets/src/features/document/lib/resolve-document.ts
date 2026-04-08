import { ApiError, documentsApi } from "@/shared/api";
import {
  getDocumentCache,
  getOfflineCreated,
  getOfflineDocumentMeta,
} from "@/shared/lib/offline/storage/store";

export interface ResolvedDocument {
  documentId: string;
  workspaceId: string;
  title?: string;
}

async function resolveDocument(documentId: string): Promise<ResolvedDocument | null> {
  const document = await documentsApi.get(documentId);
  if (document.doc_type !== "document") return null;

  return {
    documentId: document.id,
    workspaceId: document.workspace_id,
    title: document.title,
  };
}

export async function resolveDocumentWithOfflineFallback(
  documentId: string,
): Promise<ResolvedDocument | null> {
  try {
    return await resolveDocument(documentId);
  } catch (error) {
    const offline = await resolveOfflineDocument(documentId);
    if (offline) return offline;
    throw error;
  }
}

async function resolveOfflineDocument(documentId: string): Promise<ResolvedDocument | null> {
  const [offlineMeta, cacheEntry, offlineCreated] = await Promise.all([
    getOfflineDocumentMeta(documentId).catch(() => null),
    getDocumentCache(documentId).catch(() => null),
    getOfflineCreated(documentId).catch(() => null),
  ]);

  const workspaceId =
    offlineMeta?.workspaceId ?? cacheEntry?.workspaceId ?? offlineCreated?.workspaceId ?? null;

  if (!workspaceId) return null;

  return { documentId, workspaceId };
}

export function isDocumentAccessError(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 403 || error.status === 404);
}
