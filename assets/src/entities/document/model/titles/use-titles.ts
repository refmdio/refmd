import { createSignal, createEffect, type Accessor } from "solid-js";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { encryptionApi } from "@/shared/api";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import type { TitleDecryptItem } from "@/shared/lib/crypto/worker/types";
import { clientError } from "@/shared/lib/logger";
import type { DocumentResponse } from "../document/types";
import { getOfflineDek } from "@/shared/lib/offline/storage/store";
import { cacheOfflineTitle, recoverKekFromCache } from "@/shared/lib/offline/cache/manager/keys";

const titleCache = new Map<string, { title: string; nonce: string | null }>();
const pendingBatches = new Map<string, Promise<void>>();

export function injectDecryptedTitle(documentId: string, title: string, nonce?: string): void {
  titleCache.set(documentId, { title, nonce: nonce ?? null });
}

export function readCachedDecryptedTitle(documentId: string): string | null {
  return titleCache.get(documentId)?.title ?? null;
}

export function clearDocumentKeyCache(): void {
  titleCache.clear();
}

export function useDocumentTitles(
  documents: Accessor<DocumentResponse[]>,
  workspaceId: Accessor<string | null>,
) {
  const [decryptedTitles, setDecryptedTitles] = createSignal<Record<string, string>>({});
  const [retryTick, setRetryTick] = createSignal(0);
  let decryptionVersion = 0;

  createEffect(() => {
    retryTick();
    const currentVersion = ++decryptionVersion;
    const docs = documents();
    const wsId = workspaceId();
    if (!wsId || docs.length === 0) return;

    if (!cryptoWorkerReady()) return;

    const needsDecryption = docs.filter((doc) => {
      if (
        !doc.is_encrypted ||
        !doc.encrypted_title ||
        !doc.encrypted_title_nonce ||
        doc.encrypted_title_key_version == null
      )
        return false;
      const cached = titleCache.get(doc.id);
      if (!cached) return true;
      return cached.nonce !== doc.encrypted_title_nonce;
    });

    if (needsDecryption.length === 0) {
      const titles: Record<string, string> = {};
      for (const doc of docs) {
        const cached = titleCache.get(doc.id);
        if (cached) {
          titles[doc.id] = cached.title;
          if (doc.is_encrypted) {
            cacheOfflineTitle(doc.id, wsId, cached.title).catch(() => {});
          }
        }
      }
      setDecryptedTitles(titles);
      return;
    }

    const updateSignal = () => {
      if (currentVersion !== decryptionVersion) return;
      const titles: Record<string, string> = {};
      for (const d of docs) {
        const cached = titleCache.get(d.id);
        if (cached) titles[d.id] = cached.title;
      }
      setDecryptedTitles(titles);
    };

    const batchKey = `${wsId}:${needsDecryption.map((d) => d.id).join(",")}`;
    const existing = pendingBatches.get(batchKey);
    if (existing) {
      existing.then(() => {
        if (currentVersion === decryptionVersion) {
          updateSignal();
        } else {
          window.setTimeout(() => setRetryTick((value) => value + 1), 0);
          return;
        }
        const hasMissingTitles = needsDecryption.some((doc) => !titleCache.has(doc.id));
        if (hasMissingTitles) {
          window.setTimeout(() => setRetryTick((value) => value + 1), 3_000);
        }
      });
      return;
    }
    const batch = decryptBatch(needsDecryption, wsId, (docId, title, nonce) => {
      titleCache.set(docId, { title, nonce });
      if (currentVersion === decryptionVersion) {
        updateSignal();
      } else {
        window.setTimeout(() => setRetryTick((value) => value + 1), 0);
      }
      cacheOfflineTitle(docId, wsId, title).catch(() => {});
    }).finally(() => {
      pendingBatches.delete(batchKey);
      if (currentVersion !== decryptionVersion) {
        window.setTimeout(() => setRetryTick((value) => value + 1), 0);
        return;
      }
      const hasMissingTitles = needsDecryption.some((doc) => !titleCache.has(doc.id));
      if (hasMissingTitles) {
        window.setTimeout(() => setRetryTick((value) => value + 1), 3_000);
      }
    });
    pendingBatches.set(batchKey, batch);
  });

  function getTitle(doc: DocumentResponse): string {
    if (!doc.is_encrypted) return doc.title;
    return decryptedTitles()[doc.id] ?? doc.title;
  }

  function isTitleReady(doc: DocumentResponse): boolean {
    if (!doc.is_encrypted) return true;
    if (
      !doc.encrypted_title ||
      !doc.encrypted_title_nonce ||
      doc.encrypted_title_key_version == null
    ) {
      return true;
    }
    return doc.id in decryptedTitles();
  }

  return { getTitle, isTitleReady, decryptedTitles };
}

async function decryptBatch(
  docs: DocumentResponse[],
  workspaceId: string,
  onDecrypted: (docId: string, title: string, nonce: string | null) => void,
): Promise<void> {
  const worker = getCryptoWorker();

  // Best-effort active KEK resolution (not blocking — per-document
  // ensureDekForTitleDecryption resolves version-specific KEK as needed)
  try {
    await resolveActiveKek(workspaceId, getKekResolverSession());
  } catch {
    // Active KEK resolution failed; try offline KEK cache
    await recoverKekFromCache(workspaceId).catch(() => {});
  }

  // Pre-check DEK cache state for all documents in a single batch request
  const checkItems = docs
    .filter((d) => d.encrypted_title_key_version != null)
    .map((d) => ({
      requestId: d.id,
      documentId: d.id,
      keyVersion: d.encrypted_title_key_version!,
    }));
  const cachedMap = new Map<string, boolean>();
  if (checkItems.length > 0) {
    try {
      const checkResults = await worker.hasDekBatch(checkItems);
      for (const r of checkResults) cachedMap.set(r.requestId, r.hasDek);
    } catch {
      // If batch check fails, fall back to per-doc unwrap (cachedMap stays empty)
    }
  }

  // Resolve DEK only for documents that are not yet cached
  for (const doc of docs) {
    if (doc.encrypted_title_key_version == null) continue;
    if (cachedMap.get(doc.id)) continue;
    await fetchAndUnwrapDekForTitle(worker, doc, workspaceId);
  }

  const items: TitleDecryptItem[] = docs.map((doc) => ({
    documentId: doc.id,
    keyVersion: doc.encrypted_title_key_version!,
    encrypted: base64UrlDecode(doc.encrypted_title!),
    nonce: base64UrlDecode(doc.encrypted_title_nonce!),
  }));

  try {
    const results = await worker.decryptTitleBatch(items);
    for (const result of results) {
      if (result.title !== null) {
        const doc = docs.find((d) => d.id === result.documentId);
        onDecrypted(result.documentId, result.title, doc?.encrypted_title_nonce ?? null);
      }
    }
  } catch (e) {
    clientError("title_batch_decrypt_failed", { error: e });
  }
}

async function fetchAndUnwrapDekForTitle(
  worker: ReturnType<typeof getCryptoWorker>,
  doc: DocumentResponse,
  workspaceId: string,
): Promise<void> {
  const titleKeyVersion = doc.encrypted_title_key_version;
  if (titleKeyVersion == null) return;

  try {
    const dekResponse = await encryptionApi.getDocumentKeys(doc.id);
    const matchingKey = dekResponse.keys.find((key) => key.key_version === titleKeyVersion);
    if (!matchingKey) return;

    // Resolve version-specific KEK before unwrapping DEK
    if (matchingKey.kek_version) {
      await resolveKekByVersion(workspaceId, matchingKey.kek_version, getKekResolverSession());
    }

    await worker.unwrapDek({
      encryptedDek: base64UrlDecode(matchingKey.encrypted_dek),
      nonce: base64UrlDecode(matchingKey.nonce),
      documentId: doc.id,
      workspaceId,
      keyVersion: matchingKey.key_version,
      isActive: matchingKey.is_active,
      kekVersion: matchingKey.kek_version,
    });
  } catch {
    // Fallback: try offline DEK cache (DSK-wrapped)
    try {
      const offlineDek = await getOfflineDek(doc.id);
      if (offlineDek) {
        await worker.restoreDekFromOffline({
          documentId: doc.id,
          keyVersion: offlineDek.keyVersion,
          isActive: true,
        });
      }
    } catch {
      // Skip documents where offline DEK resolution also fails
    }
  }
}
