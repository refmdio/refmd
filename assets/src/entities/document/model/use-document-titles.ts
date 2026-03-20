import { createSignal, createEffect, type Accessor } from "solid-js";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { cryptoWorkerReady } from "@/shared/lib/auth-state";
import { encryptionApi } from "@/shared/api";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
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

  // Ensure KEK is resolved (needed for DEK unwrapping)
  try {
    await resolveActiveKek(workspaceId);
  } catch (e) {
    console.error("Failed to resolve KEK for title decryption:", e);
    return;
  }

  // Ensure DEKs are cached in Worker for all documents that need decryption
  for (const doc of docs) {
    const hasDek = await worker.hasDek(doc.id, doc.encrypted_title_key_version ?? undefined);
    if (!hasDek) {
      try {
        const dekResponse = await encryptionApi.getDocumentKeys(doc.id);
        const matchingKey = dekResponse.keys.find(
          (k: any) => k.key_version === doc.encrypted_title_key_version,
        );
        if (matchingKey) {
          await worker.unwrapDek({
            encryptedDek: base64UrlDecode(matchingKey.encrypted_dek),
            nonce: base64UrlDecode(matchingKey.nonce),
            documentId: doc.id,
            workspaceId,
            keyVersion: matchingKey.key_version,
          });
        }
      } catch {
        // Skip documents where DEK fetch fails
      }
    }
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
