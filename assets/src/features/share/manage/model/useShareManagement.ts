import { createSignal, onCleanup, type Accessor } from "solid-js";
import { createEffect } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import type { DocumentResponse } from "@/entities/document";
import { cryptoWorkerReady } from "@/entities/session";
import { sharesApi } from "@/shared/api";
import { createManagedShare } from "../lib/build-share";
import type { ShareListItem, UpdateShareKeysRequest } from "./types";
import {
  activeDescendantOptions as buildActiveDescendantOptions,
  expandedExclusionIds as buildExpandedExclusionIds,
  prepareFolderShareKeyUpdate,
} from "./folder-share-key-update";
import {
  forgetShareManageToken,
  readShareManageToken,
  readShareUrl,
  rememberShareAccess,
  restoreShareAccesses,
} from "../lib/manage-tokens";

function buildExpiryIso(days: number): string {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function parseOptionalNonNegativeInteger(raw: string, label: string): number | null {
  const value = raw.trim();
  if (!value) return null;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be zero or a positive integer.`);
  }
  return parsed;
}

interface UseShareManagementOptions {
  document: Accessor<DocumentResponse | null>;
  documents: Accessor<DocumentResponse[]>;
  canDeleteShares: Accessor<boolean>;
  getTitle: (document: DocumentResponse) => string;
  setError: (value: string | null) => void;
}

export function useShareManagement(options: UseShareManagementOptions) {
  const queryClient = useQueryClient();
  const [open, setOpen] = createSignal(false);
  const [permission, setPermission] = createSignal<"view" | "edit">("view");
  const [passwordEnabled, setPasswordEnabled] = createSignal(false);
  const [password, setPassword] = createSignal("");
  const [expiryDays, setExpiryDays] = createSignal<number | null>(7);
  const [accessLimit, setAccessLimit] = createSignal("");
  const [excludedDocumentIds, setExcludedDocumentIds] = createSignal<string[]>([]);
  const [creating, setCreating] = createSignal(false);
  const [createdLink, setCreatedLink] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);
  const [copiedShareId, setCopiedShareId] = createSignal<string | null>(null);
  const [updatingShareId, setUpdatingShareId] = createSignal<string | null>(null);
  const [refreshingShareId, setRefreshingShareId] = createSignal<string | null>(null);
  const [shareAccessVersion, setShareAccessVersion] = createSignal(0);
  let copiedTimer: ReturnType<typeof setTimeout> | undefined;

  const documentId = () => options.document()?.id ?? null;
  const shares = createQuery(() => ({
    queryKey: ["document-shares", documentId()],
    queryFn: () => sharesApi.listDocumentShares(documentId()!),
    enabled: open() && !!documentId(),
  }));

  const invalidate = () => {
    const id = documentId();
    if (!id) return;
    queryClient.invalidateQueries({ queryKey: ["document-shares", id] });
  };

  const resetCreateState = () => {
    setPermission("view");
    setPasswordEnabled(false);
    setPassword("");
    setExpiryDays(7);
    setAccessLimit("");
    setExcludedDocumentIds([]);
    setCreatedLink(null);
    setCopied(false);
  };

  const toggleCreateExclusion = (documentId: string, checked: boolean) => {
    setExcludedDocumentIds((current) => {
      if (checked) return current.includes(documentId) ? current : [...current, documentId];
      return current.filter((id) => id !== documentId);
    });
  };

  const createShare = async () => {
    const document = options.document();
    if (!document) return;

    setCreating(true);
    options.setError(null);
    try {
      const parsedAccessLimit = parseOptionalNonNegativeInteger(accessLimit(), "Limit");
      const days = expiryDays();
      const expiresAt = days ? buildExpiryIso(days) : null;
      const result = await createManagedShare({
        document,
        documents: options.documents(),
        permission: permission(),
        password: passwordEnabled() ? password() : "",
        expiresAt,
        accessLimit: parsedAccessLimit,
        exclusions: excludedDocumentIds(),
      });
      const link = `${window.location.origin}/share/${result.share_slug}`;
      await rememberShareAccess(document.id, result.id, {
        manageToken: result.share_manage_token,
        url: link,
      });
      setCreatedLink(link);
      invalidate();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to create share");
    } finally {
      setCreating(false);
    }
  };

  const copyCreatedLink = async () => {
    const link = createdLink();
    if (!link) return;

    try {
      await navigator.clipboard.writeText(link);
      setCopied(true);
      setCopiedShareId(null);
      if (copiedTimer) clearTimeout(copiedTimer);
      copiedTimer = setTimeout(() => {
        setCopied(false);
        copiedTimer = undefined;
      }, 2000);
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to copy share link");
    }
  };

  const canManageShare = (shareId: string) => {
    shareAccessVersion();
    const id = documentId();
    return !!id && !!readShareManageToken(id, shareId);
  };

  const canRevokeShare = (shareId: string) => canManageShare(shareId) || options.canDeleteShares();

  const shareUrl = (shareId: string) => {
    shareAccessVersion();
    const id = documentId();
    if (!id) return undefined;
    const rememberedUrl = readShareUrl(id, shareId);
    if (rememberedUrl) return rememberedUrl;

    const shareSlug = shares.data?.shares?.find((share) => share.id === shareId)?.share_slug;
    return shareSlug ? `${window.location.origin}/share/${shareSlug}` : undefined;
  };

  const copyShareLink = async (shareId: string) => {
    const link = shareUrl(shareId);
    if (!link) return;

    try {
      await navigator.clipboard.writeText(link);
      setCopiedShareId(shareId);
      setCopied(false);
      if (copiedTimer) clearTimeout(copiedTimer);
      copiedTimer = setTimeout(() => {
        setCopiedShareId(null);
        copiedTimer = undefined;
      }, 2000);
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to copy share link");
    }
  };

  const updateShareSettings = async (
    shareId: string,
    values: { expiryDays?: number | null; accessLimitInput?: string },
  ) => {
    const id = documentId();
    if (!id) return;
    const manageToken = readShareManageToken(id, shareId);
    if (!manageToken) {
      options.setError("This share can only be updated from the tab that created it.");
      return;
    }

    setUpdatingShareId(shareId);
    options.setError(null);
    try {
      const parsedAccessLimit =
        values.accessLimitInput === undefined
          ? undefined
          : parseOptionalNonNegativeInteger(values.accessLimitInput, "Limit");
      await sharesApi.updateDocumentShare(id, shareId, manageToken, {
        ...(values.expiryDays !== undefined
          ? { expires_at: values.expiryDays ? buildExpiryIso(values.expiryDays) : null }
          : {}),
        ...(parsedAccessLimit !== undefined ? { access_limit: parsedAccessLimit } : {}),
      });
      invalidate();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to update share");
    } finally {
      setUpdatingShareId(null);
    }
  };

  const activeDescendantOptions = () =>
    buildActiveDescendantOptions(options.document(), options.documents());

  const expandedExclusionIds = (excludedIds: string[]) =>
    buildExpandedExclusionIds(activeDescendantOptions(), excludedIds);

  const shareExclusionEntries = (share: ShareListItem): string[] => {
    return share.exclusions ?? [];
  };

  const refreshFolderShareKeys = async (
    share: ShareListItem,
    passwordInput = "",
    excludedIds = shareExclusionEntries(share),
  ) => {
    const document = options.document();
    const id = documentId();
    if (!id || !document || document.doc_type !== "folder") return;
    const shareId = share.id;
    const manageToken = readShareManageToken(id, shareId);
    if (!manageToken) {
      options.setError("This share can only be updated from the tab that created it.");
      return;
    }

    const password = passwordInput.trim();
    if (share.password_protected && !password) {
      options.setError("Enter the share password to refresh this folder share.");
      return;
    }
    if (share.password_protected && (!share.salt || !share.kdf_params)) {
      options.setError("This share is missing password parameters and cannot be refreshed.");
      return;
    }

    setRefreshingShareId(shareId);
    options.setError(null);
    let prepared:
      | {
          body: UpdateShareKeysRequest | null;
          shareDekEncryptionKey?: Uint8Array;
        }
      | undefined;
    try {
      prepared = await prepareFolderShareKeyUpdate({
        root: options.document(),
        documents: options.documents(),
        share,
        passwordInput,
        excludedIds,
      });
      if (!prepared.body) return;
      await sharesApi.updateShareKeys(id, shareId, manageToken, prepared.body);
      invalidate();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to refresh folder share");
    } finally {
      if (prepared?.shareDekEncryptionKey) prepared.shareDekEncryptionKey.fill(0);
      setRefreshingShareId(null);
    }
  };

  const includeFolderDescendant = async (
    share: ShareListItem,
    documentIdToInclude: string,
    passwordInput = "",
  ) => {
    const id = documentId();
    if (!id) return;
    const manageToken = readShareManageToken(id, share.id);
    if (!manageToken) {
      options.setError("This share can only be updated from the tab that created it.");
      return;
    }

    setUpdatingShareId(share.id);
    options.setError(null);
    let prepared:
      | {
          body: UpdateShareKeysRequest | null;
          shareDekEncryptionKey?: Uint8Array;
        }
      | undefined;
    let exclusionRemoved = false;
    try {
      const nextExclusions = shareExclusionEntries(share).filter(
        (excludedId) => excludedId !== documentIdToInclude,
      );
      prepared = await prepareFolderShareKeyUpdate({
        root: options.document(),
        documents: options.documents(),
        share,
        passwordInput,
        excludedIds: nextExclusions,
      });
      await sharesApi.updateShareExclusions(id, share.id, manageToken, {
        remove: [documentIdToInclude],
      });
      exclusionRemoved = true;

      if (prepared.body) {
        await sharesApi.updateShareKeys(id, share.id, manageToken, prepared.body);
      }
      invalidate();
    } catch (err) {
      if (exclusionRemoved) {
        await sharesApi
          .updateShareExclusions(id, share.id, manageToken, { add: [documentIdToInclude] })
          .catch(() => undefined);
        invalidate();
      }
      options.setError(err instanceof Error ? err.message : "Failed to include folder target");
    } finally {
      if (prepared?.shareDekEncryptionKey) prepared.shareDekEncryptionKey.fill(0);
      setUpdatingShareId(null);
    }
  };

  const updateFolderShareExclusions = async (
    shareId: string,
    values: { add: string[]; remove?: string[] } | { add?: string[]; remove: string[] },
  ) => {
    const id = documentId();
    if (!id) return;
    const manageToken = readShareManageToken(id, shareId);
    if (!manageToken) {
      options.setError("This share can only be updated from the tab that created it.");
      return;
    }

    setUpdatingShareId(shareId);
    options.setError(null);
    try {
      await sharesApi.updateShareExclusions(id, shareId, manageToken, values);
      invalidate();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to update folder exclusions");
    } finally {
      setUpdatingShareId(null);
    }
  };

  const revokeShare = async (shareId: string) => {
    const id = documentId();
    if (!id) return;
    if (!canRevokeShare(shareId)) return;

    options.setError(null);
    try {
      const manageToken = readShareManageToken(id, shareId);
      if (manageToken) {
        await sharesApi.deleteDocumentShare(id, shareId, { manageToken });
      } else {
        await sharesApi.deleteDocumentShareAsAdmin(id, shareId);
      }
      forgetShareManageToken(id, shareId);
      invalidate();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to revoke share");
    }
  };

  onCleanup(() => {
    if (copiedTimer) clearTimeout(copiedTimer);
  });

  createEffect(() => {
    const id = documentId();
    const shareIds = shares.data?.shares?.map((share) => share.id) ?? [];
    if (!open() || !id || !cryptoWorkerReady() || shareIds.length === 0) return;

    void restoreShareAccesses(id, shareIds).then(() => {
      setShareAccessVersion((version) => version + 1);
    });
  });

  return {
    open,
    setOpen,
    shares,
    permission,
    setPermission,
    passwordEnabled,
    setPasswordEnabled,
    password,
    setPassword,
    expiryDays,
    setExpiryDays,
    accessLimit,
    setAccessLimit,
    excludedDocumentIds,
    toggleCreateExclusion,
    creating,
    createdLink,
    copied,
    copiedShareId,
    createShare,
    copyCreatedLink,
    canManageShare,
    canRevokeShare,
    shareUrl,
    copyShareLink,
    updatingShareId,
    refreshingShareId,
    updateShareSettings,
    activeDescendantOptions,
    expandedExclusionIds,
    getTitle: options.getTitle,
    refreshFolderShareKeys,
    includeFolderDescendant,
    updateFolderShareExclusions,
    revokeShare,
    resetCreateState,
  };
}

export type ShareManagementModel = ReturnType<typeof useShareManagement>;
