import type { DocumentResponse } from "@/entities/document";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { prepareFolderShareKeyEntries } from "../../lib/manage/build-share";
import type { ShareChildListItem, ShareKeysUpdateDraft, ShareListItem } from "./types";

export function activeDescendantOptions(
  root: DocumentResponse | null,
  documents: DocumentResponse[],
): DocumentResponse[] {
  if (!root || root.doc_type !== "folder") return [];

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

export function expandedExclusionIds(
  descendants: DocumentResponse[],
  excludedIds: string[],
): Set<string> {
  const descendantsById = new Map(descendants.map((document) => [document.id, document]));
  const directExclusions = new Set(excludedIds);
  const expanded = new Set<string>();

  const isExcluded = (document: DocumentResponse): boolean => {
    if (directExclusions.has(document.id)) return true;
    const parent = document.parent_id ? descendantsById.get(document.parent_id) : undefined;
    return parent ? isExcluded(parent) : false;
  };

  for (const document of descendants) {
    if (isExcluded(document)) expanded.add(document.id);
  }

  return expanded;
}

function shareableDescendants(descendants: DocumentResponse[], excludedIds: string[]) {
  const excluded = expandedExclusionIds(descendants, excludedIds);
  return descendants.filter((document) => !excluded.has(document.id));
}

function shareChildEntries(share: ShareListItem): ShareChildListItem[] {
  return share.child_shares ?? [];
}

export async function prepareFolderShareKeyUpdate(options: {
  root: DocumentResponse | null;
  documents: DocumentResponse[];
  share: ShareListItem;
  shareUrl?: string;
  passwordInput: string;
  excludedIds: string[];
}): Promise<{
  body: ShareKeysUpdateDraft | null;
}> {
  const { root, documents, share, shareUrl, passwordInput, excludedIds } = options;
  if (!root || root.doc_type !== "folder") return { body: null };

  const password = passwordInput.trim();
  if (share.password_protected && !password) {
    throw new Error("Enter the share password to refresh this folder share.");
  }
  if (share.password_protected && (!share.salt || !share.kdf_params)) {
    throw new Error("This share is missing password parameters and cannot be refreshed.");
  }

  const prepared = await getCryptoWorker().prepareManagedShareSecrets({
    shareUrl: requireShareUrl(shareUrl),
    ...(share.password_protected
      ? {
          password,
          salt: share.salt!,
          kdfParams: share.kdf_params!,
        }
      : {}),
  });
  const shareSlug = prepared.shareSlug;

  try {
    const descendants = shareableDescendants(activeDescendantOptions(root, documents), excludedIds);
    const childByDocumentId = new Map(
      shareChildEntries(share).map((child) => [child.document_id, child.share_id]),
    );
    const addTargets = descendants
      .filter((descendant) => !childByDocumentId.has(descendant.id))
      .map((descendant) => ({ documentId: descendant.id }));
    const replaceTargets = descendants
      .map((descendant) => {
        const existingShareId = childByDocumentId.get(descendant.id);
        return existingShareId
          ? { documentId: descendant.id, shareId: existingShareId }
          : undefined;
      })
      .filter((target): target is { documentId: string; shareId: string } => Boolean(target));

    if (addTargets.length === 0 && replaceTargets.length === 0) {
      return { body: null };
    }

    return {
      body: {
        add_keys: await prepareFolderShareKeyEntries(root, documents, {
          shareSlug,
          targets: addTargets,
        }),
        replace_keys: await prepareFolderShareKeyEntries(root, documents, {
          shareSlug,
          targets: replaceTargets,
        }),
      },
    };
  } finally {
    await getCryptoWorker()
      .clearShareSecrets(shareSlug)
      .catch(() => undefined);
  }
}

function requireShareUrl(shareUrl?: string): string {
  if (!shareUrl) {
    throw new Error("This share can only be updated from a tab with the full share link.");
  }
  return shareUrl;
}
