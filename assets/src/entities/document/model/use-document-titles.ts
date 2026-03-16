import { createSignal, createEffect, type Accessor } from "solid-js";
import { encryptionApi } from "@/shared/api";
import { base64UrlDecode, unwrapDek, decryptTitle } from "@/shared/lib/crypto";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { authState, deviceState } from "@/shared/lib/auth-state";
import type { DocumentResponse } from "./types";

const dekCache = new Map<string, { dek: Uint8Array; keyVersion: number }>();
const titleCache = new Map<string, { title: string; nonce: string | null }>();

export function injectDecryptedTitle(documentId: string, title: string, nonce?: string): void {
  titleCache.set(documentId, { title, nonce: nonce ?? null });
}

export function clearDocumentKeyCache(): void {
  dekCache.clear();
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

    const auth = authState();
    const device = deviceState();
    if (!auth?.umk || !auth.identityKeys || !device?.deviceEcdhPrivate) return;

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

    decryptBatch(needsDecryption, wsId, auth, device, (docId, title, nonce) => {
      titleCache.set(docId, { title, nonce });
      updateSignal();
    });
  });

  function getTitle(doc: DocumentResponse): string {
    if (!doc.is_encrypted) return doc.title;
    return decryptedTitles()[doc.id] ?? doc.title;
  }

  return { getTitle, decryptedTitles };
}

async function decryptBatch(
  docs: DocumentResponse[],
  workspaceId: string,
  auth: NonNullable<ReturnType<typeof authState>>,
  device: NonNullable<ReturnType<typeof deviceState>>,
  onDecrypted: (docId: string, title: string, nonce: string | null) => void,
): Promise<void> {
  const concurrency = 5;

  for (let i = 0; i < docs.length; i += concurrency) {
    const batch = docs.slice(i, i + concurrency);
    const promises = batch.map(async (doc) => {
      try {
        const title = await decryptDocumentTitle(doc, workspaceId, auth, device);
        onDecrypted(doc.id, title, doc.encrypted_title_nonce ?? null);
      } catch (e) {
        console.error(`Failed to decrypt title for document ${doc.id}:`, e);
      }
    });
    await Promise.all(promises);
  }
}

async function decryptDocumentTitle(
  doc: DocumentResponse,
  workspaceId: string,
  auth: NonNullable<ReturnType<typeof authState>>,
  device: NonNullable<ReturnType<typeof deviceState>>,
): Promise<string> {
  const keyVersion = doc.encrypted_title_key_version!;

  let dek: Uint8Array;
  const cached = dekCache.get(doc.id);
  if (cached && cached.keyVersion === keyVersion) {
    dek = cached.dek;
  } else {
    const { kek } = await resolveActiveKek(
      workspaceId,
      { user: auth.user, umk: auth.umk!, identityKeys: auth.identityKeys! },
      { deviceId: device.deviceId, deviceEcdhPrivate: device.deviceEcdhPrivate! },
    );

    const keysResponse = await encryptionApi.getDocumentKeys(doc.id);
    const keyEntry = keysResponse.keys.find((k) => k.key_version === keyVersion);
    if (!keyEntry) throw new Error(`DEK key_version ${keyVersion} not found`);

    dek = unwrapDek(
      base64UrlDecode(keyEntry.encrypted_dek),
      base64UrlDecode(keyEntry.nonce),
      kek,
      doc.id,
      workspaceId,
    );
    dekCache.set(doc.id, { dek, keyVersion });
  }

  return decryptTitle(
    base64UrlDecode(doc.encrypted_title!),
    base64UrlDecode(doc.encrypted_title_nonce!),
    dek,
    doc.id,
    keyVersion,
  );
}
