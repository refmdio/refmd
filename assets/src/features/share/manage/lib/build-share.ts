import type { DocumentResponse } from "@/entities/document";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";
import { encryptionApi, sharesApi, type components } from "@/shared/api";
import { base64UrlDecode, base64UrlEncode, randomBytes } from "@/shared/lib/crypto/encoding";
import { TARGET_KDF_PARAMS, deriveAuthKeys } from "@/shared/lib/crypto/kdf";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { wrapShareDek } from "@/shared/lib/crypto/share-dek";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

type SharePermission = "view" | "edit";
type ShareScope = "document" | "folder";

export interface CreateShareOptions {
  document: DocumentResponse;
  documents: DocumentResponse[];
  permission: SharePermission;
  password?: string;
  expiresAt?: string | null;
  accessLimit?: number | null;
  exclusions?: string[];
}

interface PreparedShareKey {
  encryptedDek: string;
  nonce: string | null;
}

interface FolderShareKeyTarget {
  documentId: string;
  shareId?: string;
}

function generateShareSlug(): string {
  return base64UrlEncode(randomBytes(16));
}

function activeDescendants(
  root: DocumentResponse,
  documents: DocumentResponse[],
): DocumentResponse[] {
  const byParent = new Map<string | null, DocumentResponse[]>();
  for (const document of documents) {
    if (document.archived_at) continue;
    const siblings = byParent.get(document.parent_id ?? null) ?? [];
    siblings.push(document);
    byParent.set(document.parent_id ?? null, siblings);
  }

  const result: DocumentResponse[] = [];
  const visit = (parentId: string) => {
    for (const child of byParent.get(parentId) ?? []) {
      result.push(child);
      if (child.doc_type === "folder") visit(child.id);
    }
  };

  visit(root.id);
  return result;
}

function expandExcludedDescendants(
  descendants: DocumentResponse[],
  excludedIds: string[],
): Set<string> {
  const byParent = new Map<string | null, DocumentResponse[]>();
  for (const document of descendants) {
    const siblings = byParent.get(document.parent_id ?? null) ?? [];
    siblings.push(document);
    byParent.set(document.parent_id ?? null, siblings);
  }

  const expanded = new Set(excludedIds);
  const visit = (parentId: string) => {
    for (const child of byParent.get(parentId) ?? []) {
      expanded.add(child.id);
      if (child.doc_type === "folder") visit(child.id);
    }
  };

  for (const excludedId of excludedIds) visit(excludedId);
  return expanded;
}

function shareableDescendants(
  root: DocumentResponse,
  documents: DocumentResponse[],
  exclusions: string[] = [],
): DocumentResponse[] {
  const descendants = activeDescendants(root, documents);
  if (exclusions.length === 0) return descendants;

  const descendantIds = new Set(descendants.map((document) => document.id));
  const excludedIds = exclusions.filter((documentId) => descendantIds.has(documentId));
  const expandedExclusions = expandExcludedDescendants(descendants, excludedIds);
  return descendants.filter((document) => !expandedExclusions.has(document.id));
}

async function ensureDocumentDekCached(document: DocumentResponse): Promise<number> {
  const worker = getCryptoWorker();
  const keysResponse = await encryptionApi.getDocumentKeys(document.id);
  const activeKey = keysResponse.keys.find((key) => key.is_active);
  if (!activeKey) throw new Error("No active document key");

  if (await worker.hasDek(document.id, activeKey.key_version)) {
    return activeKey.key_version;
  }

  await resolveKekByVersion(document.workspace_id, activeKey.kek_version, getKekResolverSession());
  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(activeKey.encrypted_dek),
    nonce: base64UrlDecode(activeKey.nonce),
    documentId: document.id,
    workspaceId: document.workspace_id,
    keyVersion: activeKey.key_version,
    kekVersion: activeKey.kek_version,
    isActive: activeKey.is_active,
  });

  return activeKey.key_version;
}

async function prepareShareKey(
  document: DocumentResponse,
  shareId: string,
  shareDekEncryptionKey?: Uint8Array,
): Promise<PreparedShareKey> {
  if (document.doc_type === "folder") {
    const folderDek = randomBytes(32);
    const wrapped = shareDekEncryptionKey
      ? wrapShareDek({
          dek: folderDek,
          dekEncryptionKey: shareDekEncryptionKey,
          shareId,
          documentId: document.id,
        })
      : { encryptedDek: folderDek, nonce: null };

    return {
      encryptedDek: base64UrlEncode(wrapped.encryptedDek),
      nonce: wrapped.nonce ? base64UrlEncode(wrapped.nonce) : null,
    };
  }

  const keyVersion = await ensureDocumentDekCached(document);
  const wrapped = await getCryptoWorker().wrapDekForShare({
    documentId: document.id,
    shareId,
    keyVersion,
    shareDekEncryptionKey,
  });

  return {
    encryptedDek: base64UrlEncode(wrapped.encryptedDek),
    nonce: wrapped.nonce ? base64UrlEncode(wrapped.nonce) : null,
  };
}

export async function deriveShareDekEncryptionKey(
  password: string,
  salt: string,
  kdfParams: components["schemas"]["KdfParams"],
): Promise<Uint8Array> {
  const derived = await deriveAuthKeys(password, salt, kdfParams);
  const shareDekEncryptionKey = base64UrlDecode(derived.shareDekEncryptionKeyBase64);
  derived.pdk.fill(0);
  derived.puk.fill(0);
  return shareDekEncryptionKey;
}

export async function prepareFolderShareKeyEntries(
  root: DocumentResponse,
  documents: DocumentResponse[],
  options: {
    shareDekEncryptionKey?: Uint8Array;
    targets?: FolderShareKeyTarget[];
  } = {},
): Promise<
  Array<{
    document_id: string;
    share_id: string;
    encrypted_dek: string;
    nonce: string | null;
  }>
> {
  const descendants = activeDescendants(root, documents);
  const descendantsById = new Map(descendants.map((document) => [document.id, document]));
  const targets: FolderShareKeyTarget[] =
    options.targets ??
    descendants.map((document) => ({
      documentId: document.id,
    }));

  return Promise.all(
    targets.map(async (target) => {
      const document = descendantsById.get(target.documentId);
      if (!document) throw new Error("Share target is no longer available.");

      const childShareId = target.shareId ?? crypto.randomUUID();
      const childKey = await prepareShareKey(document, childShareId, options.shareDekEncryptionKey);
      return {
        document_id: document.id,
        share_id: childShareId,
        encrypted_dek: childKey.encryptedDek,
        nonce: childKey.nonce,
      };
    }),
  );
}

export async function createManagedShare(options: CreateShareOptions) {
  if (!cryptoWorkerReady()) throw new Error("Crypto worker not ready");

  const root = options.document;
  const scope: ShareScope = root.doc_type === "folder" ? "folder" : "document";
  const shareId = crypto.randomUUID();
  const shareSlug = generateShareSlug();
  const password = options.password?.trim() ?? "";

  let passwordFields:
    | { auth_key: string; kdf_params: components["schemas"]["KdfParams"]; salt: string }
    | undefined;
  let shareDekEncryptionKey: Uint8Array | undefined;

  if (password) {
    const salt = randomBytes(16);
    const derived = await deriveAuthKeys(password, base64UrlEncode(salt), TARGET_KDF_PARAMS);
    passwordFields = {
      auth_key: derived.shareAuthKeyBase64,
      kdf_params: TARGET_KDF_PARAMS,
      salt: base64UrlEncode(salt),
    };
    shareDekEncryptionKey = base64UrlDecode(derived.shareDekEncryptionKeyBase64);
    derived.pdk.fill(0);
    derived.puk.fill(0);
  }

  try {
    const rootKey = await prepareShareKey(root, shareId, shareDekEncryptionKey);
    const base = {
      id: shareId,
      share_slug: shareSlug,
      token_prefix: shareSlug.slice(0, 4),
      permission: options.permission,
      password_protected: Boolean(password),
      encrypted_dek: rootKey.encryptedDek,
      nonce: rootKey.nonce,
      expires_at: options.expiresAt ?? null,
      access_limit: options.accessLimit ?? null,
      ...passwordFields,
    };

    const body: components["schemas"]["CreateShareRequest"] =
      scope === "folder"
        ? {
            ...base,
            scope,
            exclusions: options.exclusions ?? [],
            share_keys: await Promise.all(
              shareableDescendants(root, options.documents, options.exclusions).map(
                async (document) => {
                  const childShareId = crypto.randomUUID();
                  const childKey = await prepareShareKey(
                    document,
                    childShareId,
                    shareDekEncryptionKey,
                  );
                  return {
                    document_id: document.id,
                    share_id: childShareId,
                    encrypted_dek: childKey.encryptedDek,
                    nonce: childKey.nonce,
                  };
                },
              ),
            ),
          }
        : { ...base, scope };

    return await sharesApi.createDocumentShare(root.id, body);
  } finally {
    if (shareDekEncryptionKey) shareDekEncryptionKey.fill(0);
  }
}
