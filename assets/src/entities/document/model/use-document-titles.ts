import { createSignal, createEffect, type Accessor } from "solid-js";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { cryptoWorkerReady } from "@/shared/lib/auth-state";
import { encryptionApi } from "@/shared/api";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import type { TitleDecryptItem } from "@/shared/lib/crypto/worker/types";
import type { DocumentResponse } from "./types";

const titleCache = new Map<string, { title: string; nonce: string | null }>();

export function injectDecryptedTitle(documentId: string, title: string, nonce?: string): void {
  titleCache.set(documentId, { title, nonce: nonce ?? null });
}

export function clearDocumentKeyCache(): void {
  titleCache.clear();
}

export function useDocumentTitles(
  documents: Accessor<DocumentResponse[]>,
  workspaceId: Accessor<string | null>,
) {
  const [decryptedTitles, setDecryptedTitles] = createSignal<Record<string, string>>({});

  createEffect(() => {
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
        if (cached) titles[doc.id] = cached.title;
      }
      setDecryptedTitles(titles);
      return;
    }

    const updateSignal = () => {
      const titles: Record<string, string> = {};
      for (const d of docs) {
        const cached = titleCache.get(d.id);
        if (cached) titles[d.id] = cached.title;
      }
      setDecryptedTitles(titles);
    };

    decryptBatch(needsDecryption, wsId, (docId, title, nonce) => {
      titleCache.set(docId, { title, nonce });
      updateSignal();
    });
  });

  function getTitle(doc: DocumentResponse): string {
    if (!doc.is_encrypted) return doc.title;
    return decryptedTitles()[doc.id] ?? doc.title;
  }

  function isTitleReady(doc: DocumentResponse): boolean {
    if (!doc.is_encrypted) return true;
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
    await resolveActiveKek(workspaceId);
  } catch {
    // Active KEK resolution failed; per-document resolution will handle individual versions
  }

  // Ensure DEKs are cached for each document (resolves version-specific KEK if needed)
  for (const doc of docs) {
    await ensureDekForTitleDecryption(worker, doc, workspaceId);
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
    console.error("Failed to decrypt title batch:", e);
  }
}

async function ensureDekForTitleDecryption(
  worker: ReturnType<typeof getCryptoWorker>,
  doc: DocumentResponse,
  workspaceId: string,
): Promise<void> {
  const titleKeyVersion = doc.encrypted_title_key_version;
  if (titleKeyVersion == null) return;

  const hasDek = await worker.hasDek(doc.id, titleKeyVersion);
  if (hasDek) return;

  try {
    const dekResponse = await encryptionApi.getDocumentKeys(doc.id);
    const matchingKey = dekResponse.keys.find((k: any) => k.key_version === titleKeyVersion);
    if (!matchingKey) return;

    // Resolve version-specific KEK before unwrapping DEK
    if (matchingKey.kek_version) {
      await resolveKekByVersion(workspaceId, matchingKey.kek_version);
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
    // Skip documents where DEK resolution fails
  }
}
