import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import type { TitleDecryptItem, TitleDecryptResult } from "../types";
import type { WorkerKeyState } from "../state";
import { evictCachedDek, getCachedDek, setActiveDekVersion, setCachedDek } from "../state";
import { randomBytes } from "../../encoding";
import {
  buildDocumentContentAad,
  buildOfflineDekCacheAad,
  buildOfflineDocumentCacheAad,
  buildOfflinePendingChangesAad,
} from "../../aad";
import { decryptTitle, encryptTitle, generateDek, unwrapDek, wrapDek } from "../../dek";
import {
  dskDecrypt,
  dskEncrypt,
  type HandlerPayload,
  requireDekForDocument,
  requireDsk,
  requireKekForWorkspace,
} from "./utils";

export function handleGenerateDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const workspaceId = p.workspaceId as string;
  const setActive = (p.setActive as boolean) !== false;
  const { kek, keyVersion: kekVersion } = requireKekForWorkspace(state, workspaceId);

  const dek = generateDek();
  const dekKeyVersion = (p.dekKeyVersion as number) ?? 1;
  setCachedDek(state, documentId, dek, dekKeyVersion);
  if (setActive) {
    setActiveDekVersion(state, documentId, dekKeyVersion);
  }

  const { encryptedDek, nonce } = wrapDek(dek, kek, documentId, workspaceId);
  return { encryptedDek, nonce, keyVersion: kekVersion };
}

export function handleWrapDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number | undefined;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { encryptedDek, nonce } = wrapDek(dek, kek, documentId, workspaceId);
  return { encryptedDek, nonce };
}

export function handleUnwrapDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const encryptedDek = p.encryptedDek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const isActive = p.isActive as boolean | undefined;
  const kekVersion = p.kekVersion as number | undefined;
  const { kek } = requireKekForWorkspace(state, workspaceId, kekVersion);

  const dek = unwrapDek(encryptedDek, nonce, kek, documentId, workspaceId);
  setCachedDek(state, documentId, dek, keyVersion);
  if (isActive) {
    setActiveDekVersion(state, documentId, keyVersion);
  }
  return { status: "ok" };
}

export function handleEncryptTitle(state: WorkerKeyState, p: HandlerPayload): unknown {
  const title = p.title as string;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const result = encryptTitle(title, dek, documentId, keyVersion);
  return { encrypted: result.encrypted, nonce: result.nonce };
}

export function handleDecryptTitle(state: WorkerKeyState, p: HandlerPayload): unknown {
  const encrypted = p.encrypted as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const title = decryptTitle(encrypted, nonce, dek, documentId, keyVersion);
  return { title };
}

export function handleDecryptTitleBatch(state: WorkerKeyState, p: HandlerPayload): unknown {
  const items = p.items as TitleDecryptItem[];
  const results: TitleDecryptResult[] = [];

  for (const item of items) {
    try {
      const cached = getCachedDek(state, item.documentId, item.keyVersion);
      if (!cached) {
        results.push({ documentId: item.documentId, title: null });
        continue;
      }
      const title = decryptTitle(
        item.encrypted,
        item.nonce,
        cached.dek,
        item.documentId,
        item.keyVersion,
      );
      results.push({ documentId: item.documentId, title });
    } catch {
      results.push({ documentId: item.documentId, title: null });
    }
  }

  return results;
}

export function handleEncryptContent(state: WorkerKeyState, p: HandlerPayload): unknown {
  const plaintext = p.plaintext as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const nonce = randomBytes(24);
  const aad = buildDocumentContentAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

export function handleDecryptContent(state: WorkerKeyState, p: HandlerPayload): unknown {
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const aad = buildDocumentContentAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const plaintext = cipher.decrypt(ciphertext);

  return { plaintext };
}

export function handleHasDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const requiredVersion = p.keyVersion as number | undefined;
  const cached = getCachedDek(state, documentId, requiredVersion);
  return { hasDek: !!cached };
}

export function handleCacheDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const dek = p.dek as Uint8Array;
  const keyVersion = p.keyVersion as number;
  setCachedDek(state, documentId, dek, keyVersion);
  return { status: "ok" };
}

export function handleEvictDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  evictCachedDek(state, documentId, keyVersion);
  return { status: "ok" };
}

export function handleEncryptOfflineCache(state: WorkerKeyState, p: HandlerPayload): unknown {
  const plaintext = p.plaintext as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const nonce = randomBytes(24);
  const aad = buildOfflineDocumentCacheAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

export function handleDecryptOfflineCache(state: WorkerKeyState, p: HandlerPayload): unknown {
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const aad = buildOfflineDocumentCacheAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const plaintext = cipher.decrypt(ciphertext);

  return { plaintext };
}

export function handleEncryptOfflinePending(state: WorkerKeyState, p: HandlerPayload): unknown {
  const plaintext = p.plaintext as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const nonce = randomBytes(24);
  const aad = buildOfflinePendingChangesAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

export function handleDecryptOfflinePending(state: WorkerKeyState, p: HandlerPayload): unknown {
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const aad = buildOfflinePendingChangesAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const plaintext = cipher.decrypt(ciphertext);

  return { plaintext };
}

export async function handleWrapDekForOffline(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  const aad = buildOfflineDekCacheAad(documentId, keyVersion);
  return await dskEncrypt(dsk, dek, aad);
}

export async function handleUnwrapDekFromOffline(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = p.ciphertext as ArrayBuffer;
  const iv = p.iv as ArrayBuffer;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const isActive = (p.isActive as boolean | undefined) ?? true;

  const dek = await dskDecrypt(
    dsk,
    ciphertext,
    iv,
    buildOfflineDekCacheAad(documentId, keyVersion),
  );
  setCachedDek(state, documentId, dek, keyVersion);
  if (isActive) {
    setActiveDekVersion(state, documentId, keyVersion);
  }
  return { restored: true };
}
