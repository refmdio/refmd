import { type Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { documentsApi } from "@/shared/api";
import { authState, cryptoWorkerReady } from "@/shared/lib/auth-state";
import {
  putOfflineDocumentIndex,
  getOfflineDocumentIndex,
  getOfflineDocumentMeta,
} from "@/shared/lib/offline/offline-store";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { buildOfflineDocumentCacheAad } from "@/shared/lib/crypto/aad";

export function useDocuments(workspaceId: Accessor<string | null>) {
  const query = createQuery(() => ({
    queryKey: ["documents", workspaceId()],
    queryFn: async () => {
      const wsId = workspaceId()!;
      try {
        const result = await documentsApi.list(wsId);
        putOfflineDocumentIndex(
          wsId,
          result.documents.map((doc) => ({
            documentId: doc.id,
            workspaceId: doc.workspace_id,
            parentId: doc.parent_id ?? null,
            position: doc.position,
            docType: doc.doc_type,
            folderTitle: doc.doc_type === "folder" ? (doc.title ?? null) : null,
            archivedAt: doc.archived_at ?? null,
            isEncrypted: doc.is_encrypted,
            updatedAt: doc.updated_at,
          })),
        ).catch(() => {});
        return result;
      } catch (err) {
        const cached = await getOfflineDocumentIndex(wsId).catch(() => []);
        if (cached.length > 0) {
          // Attempt to decrypt titles from offline-documents DSK-encrypted metadata
          const worker = getCryptoWorker();
          const titleMap = new Map<string, string>();
          for (const entry of cached) {
            if (entry.isEncrypted) {
              try {
                const meta = await getOfflineDocumentMeta(entry.documentId);
                if (meta?.encryptedTitle && meta.encryptedTitleNonce) {
                  const aad = buildOfflineDocumentCacheAad(entry.documentId, 0);
                  const plaintext = await worker.unwrapWithDsk({
                    ciphertext: meta.encryptedTitle.buffer as ArrayBuffer,
                    iv: meta.encryptedTitleNonce.buffer as ArrayBuffer,
                    aad,
                  });
                  titleMap.set(entry.documentId, new TextDecoder().decode(plaintext));
                }
              } catch {
                // DSK not available or decryption failed
              }
            }
          }

          return {
            documents: cached.map((entry) => ({
              id: entry.documentId,
              workspace_id: entry.workspaceId,
              parent_id: entry.parentId,
              position: entry.position,
              doc_type: entry.docType,
              title: titleMap.get(entry.documentId) ?? entry.folderTitle ?? "Untitled",
              archived_at: entry.archivedAt,
              is_encrypted: entry.isEncrypted,
              updated_at: entry.updatedAt,
              created_at: entry.updatedAt,
              created_by: null,
              encrypted_title: null,
              encrypted_title_nonce: null,
              encrypted_title_key_version: null,
              active_snapshot_id: null,
              latest_snapshot_at: null,
              latest_update_at: null,
              min_dek_version: 0,
              needs_dek_rotation: false,
              slug: "",
            })),
          };
        }
        throw err;
      }
    },
    enabled: !!authState() && cryptoWorkerReady() && !!workspaceId(),
  }));

  const flatDocuments = () => query.data?.documents ?? [];

  return { flatDocuments, query };
}
