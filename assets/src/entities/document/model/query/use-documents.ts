import { type Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { documentsApi } from "@/shared/api";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import {
  deleteOfflineCreated,
  putOfflineDocumentIndex,
  getOfflineDocumentIndex,
  getOfflineDocumentMeta,
  getOfflineDek,
  type OfflineDocumentWriteState,
} from "@/shared/lib/offline/storage/store";
import { shouldPreferOfflineCache } from "@/shared/lib/offline/offline-state";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { toArrayBuffer } from "@/shared/lib/storage/idb";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";

export function offlineDocumentWriteState(entry: {
  archivedAt: string | null;
  writeState?: OfflineDocumentWriteState | null;
}): OfflineDocumentWriteState {
  return entry.writeState ?? (entry.archivedAt ? "archived" : "writable");
}

export function documentWriteStateForOfflineIndex(doc: {
  archived_at?: string | null;
  write_state?: OfflineDocumentWriteState | null;
}): OfflineDocumentWriteState {
  return doc.write_state ?? (doc.archived_at ? "archived" : "writable");
}

async function loadOfflineDocuments(wsId: string) {
  let cached: Awaited<ReturnType<typeof getOfflineDocumentIndex>> | null = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    cached = await getOfflineDocumentIndex(wsId).catch(() => null);
    if (cached !== null) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (cached === null) return null;

  // Attempt to decrypt titles from offline-documents DSK-encrypted metadata.
  const titleMap = new Map<string, string>();
  try {
    const worker = getCryptoWorker();
    for (const entry of cached) {
      if (entry.isEncrypted) {
        let recovered = false;
        try {
          const meta = await getOfflineDocumentMeta(entry.documentId);
          if (
            meta?.encryptedTitle &&
            meta.encryptedTitleNonce &&
            meta.encryptedTitle.byteLength > 0 &&
            meta.encryptedTitleNonce.byteLength > 0
          ) {
            const plaintext = await worker.unwrapOfflineDocumentTitleWithDsk({
              ciphertext: toArrayBuffer(meta.encryptedTitle),
              iv: toArrayBuffer(meta.encryptedTitleNonce),
              documentId: entry.documentId,
              keyVersion: 0,
            });
            titleMap.set(entry.documentId, new TextDecoder().decode(plaintext));
            recovered = true;
          }
        } catch {
          // DSK not available or decryption failed.
        }
        if (
          !recovered &&
          entry.encryptedTitle &&
          entry.encryptedTitleNonce &&
          entry.encryptedTitleKeyVersion != null
        ) {
          try {
            const offlineDek = await getOfflineDek(entry.documentId);
            if (offlineDek) {
              await worker.restoreDekFromOffline({
                documentId: entry.documentId,
                keyVersion: offlineDek.keyVersion,
                isActive: true,
              });
            }
            const title = await worker.decryptTitle({
              encrypted: base64UrlDecode(entry.encryptedTitle),
              nonce: base64UrlDecode(entry.encryptedTitleNonce),
              documentId: entry.documentId,
              keyVersion: entry.encryptedTitleKeyVersion,
            });
            titleMap.set(entry.documentId, title);
          } catch {
            // Offline DEK or title decryption failed.
          }
        }
      }
    }
  } catch {
    // Offline listing should remain available even if title recovery fails.
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
      is_published: false,
      can_sync_publication: false,
      write_state: offlineDocumentWriteState(entry),
      updated_at: entry.updatedAt,
      created_at: entry.updatedAt,
      created_by: null,
      encrypted_title: entry.encryptedTitle ?? null,
      encrypted_title_nonce: entry.encryptedTitleNonce ?? null,
      encrypted_title_key_version: entry.encryptedTitleKeyVersion ?? null,
      active_snapshot_id: null,
      latest_snapshot_at: null,
      latest_update_at: null,
      min_dek_version: 0,
      needs_dek_rotation: false,
      dek_rotation_reason: null,
      needs_rotation_snapshot: false,
      slug: "",
    })),
  };
}

export function useDocuments(workspaceId: Accessor<string | null>) {
  const query = createQuery(() => ({
    queryKey: ["documents", workspaceId()],
    queryFn: async () => {
      const wsId = workspaceId()!;
      if (shouldPreferOfflineCache()) {
        const cached = await loadOfflineDocuments(wsId);
        if (cached !== null) return cached;
      }
      try {
        const result = await documentsApi.list(wsId);
        for (const doc of result.documents) {
          if (doc.active_snapshot_id) {
            deleteOfflineCreated(doc.id).catch(() => {});
          }
        }
        putOfflineDocumentIndex(
          wsId,
          result.documents.map((doc) => ({
            documentId: doc.id,
            workspaceId: doc.workspace_id,
            parentId: doc.parent_id ?? null,
            position: doc.position,
            docType: doc.doc_type,
            folderTitle: doc.doc_type === "folder" ? (doc.title ?? null) : null,
            encryptedTitle: doc.encrypted_title ?? null,
            encryptedTitleNonce: doc.encrypted_title_nonce ?? null,
            encryptedTitleKeyVersion: doc.encrypted_title_key_version ?? null,
            archivedAt: doc.archived_at ?? null,
            writeState: documentWriteStateForOfflineIndex(doc),
            isEncrypted: doc.is_encrypted,
            updatedAt: doc.updated_at,
          })),
        ).catch(() => {});
        return result;
      } catch (err) {
        const cached = await loadOfflineDocuments(wsId);
        if (cached !== null) return cached;
        throw err;
      }
    },
    enabled:
      !!authState() &&
      !!deviceState() &&
      !!workspaceId() &&
      (cryptoWorkerReady() || shouldPreferOfflineCache()),
  }));

  const flatDocuments = () => query.data?.documents ?? [];

  return { flatDocuments, query };
}
