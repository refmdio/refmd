import { createEffect, createMemo, createSignal, type Accessor } from "solid-js";
import { loadMountTrustAnchor, useShareMounts } from "@/entities/mount";
import type { MountedShareTreeEntry, ShareMount, ShareTreeEntry } from "@/entities/mount";
import { getRateLimitRetryMs } from "@/shared/api";
import { Notice } from "@/shared/lib/notice";
import { ensureShareParticipantDeviceReady } from "../../lib/session/session";
import { resolveShareTitle } from "../../lib/route/title";
import {
  resolveMountedShareTitle,
  respondShareMountPasswordChallenge,
} from "../../lib/route/mount";
import { deleteShareMount, getShareMount, getShareMountFolder } from "../../lib/mount/share";
import {
  assertWorkspacePinBootstrapEnvelope,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import { registerBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";

function rootExpansionKey(mount: ShareMount): string {
  return mount.id;
}

function entryExpansionKey(mount: ShareMount, entry: ShareTreeEntry): string {
  if (!entry.folder_token) throw new Error("mount_folder_token_unavailable");
  return `${mount.id}:${entry.folder_token}`;
}

function subtreeCacheKey(mount: ShareMount, folderToken: string, redeemAttemptId: string): string {
  return `${mount.id}:${folderToken}:${redeemAttemptId}`;
}

function optionalWorkspacePinBootstrapEnvelope(
  value: unknown,
): WorkspacePinBootstrapEnvelope | null | undefined {
  if (value === undefined || value === null) return value;
  return assertWorkspacePinBootstrapEnvelope(value, "mount_workspace_pin_bootstrap_invalid");
}

let persistedExpandedMounts = new Set<string>();
let persistedMountEntries = new Map<string, MountedShareTreeEntry[]>();
let persistedMountEntryCacheKeys = new Map<string, string>();

function clearMountSubtreeMemory(): void {
  persistedExpandedMounts = new Set<string>();
  persistedMountEntries = new Map<string, MountedShareTreeEntry[]>();
  persistedMountEntryCacheKeys = new Map<string, string>();
}

registerBeforeSessionCleanup(clearMountSubtreeMemory);

function genericShareTitle(title: string, targetKind: ShareMount["target_kind"]): boolean {
  return title === (targetKind === "folder" ? "Shared folder" : "Shared document");
}

async function delay(ms: number): Promise<void> {
  await new Promise((resolve) => window.setTimeout(resolve, ms));
}

interface UseShareMountTreeOptions {
  workspaceId: Accessor<string | null | undefined>;
  deviceReady: Accessor<boolean>;
}

export function useShareMountTree(options: UseShareMountTreeOptions) {
  const { query: mountsQuery, mounts } = useShareMounts(options.workspaceId);
  const [expandedMounts, setExpandedMountsSignal] = createSignal(
    new Set<string>(persistedExpandedMounts),
  );
  const [loadingMounts, setLoadingMounts] = createSignal(new Set<string>());
  const [mountEntries, setMountEntriesSignal] = createSignal(
    new Map<string, MountedShareTreeEntry[]>(persistedMountEntries),
  );
  const [mountEntryCacheKeys, setMountEntryCacheKeysSignal] = createSignal(
    new Map<string, string>(persistedMountEntryCacheKeys),
  );
  const [resolvedMountTitles, setResolvedMountTitles] = createSignal(new Map<string, string>());
  const [passwordMount, setPasswordMount] = createSignal<ShareMount | null>(null);
  const [mountPassword, setMountPassword] = createSignal("");
  const [mountPasswordError, setMountPasswordError] = createSignal<string | null>(null);
  const [submittingMountPassword, setSubmittingMountPassword] = createSignal(false);
  let previousWorkspaceId: string | null | undefined = options.workspaceId();

  const resolvedMounts = createMemo(() =>
    mounts().map((mount) => {
      const title = resolvedMountTitles().get(mount.id);
      return title ? { ...mount, resolved_title: title } : mount;
    }),
  );

  const setExpandedMounts = (update: (current: Set<string>) => Set<string>) => {
    setExpandedMountsSignal((current) => {
      const next = update(current);
      persistedExpandedMounts = new Set(next);
      return next;
    });
  };

  const setMountEntries = (
    update: (current: Map<string, MountedShareTreeEntry[]>) => Map<string, MountedShareTreeEntry[]>,
  ) => {
    setMountEntriesSignal((current) => {
      const next = update(current);
      persistedMountEntries = new Map(next);
      return next;
    });
  };

  const setMountEntryCacheKeys = (
    update: (current: Map<string, string>) => Map<string, string>,
  ) => {
    setMountEntryCacheKeysSignal((current) => {
      const next = update(current);
      persistedMountEntryCacheKeys = new Map(next);
      return next;
    });
  };

  const setMountLoading = (key: string, loading: boolean) => {
    setLoadingMounts((current) => {
      const next = new Set(current);
      if (loading) next.add(key);
      else next.delete(key);
      return next;
    });
  };

  const toggleMountKey = (key: string): boolean => {
    let expanded = false;
    setExpandedMounts((current) => {
      const next = new Set(current);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
        expanded = true;
      }
      return next;
    });
    return expanded;
  };

  const resolveMountRootTitle = async (mount: ShareMount): Promise<string | null> => {
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const anchor = await loadMountTrustAnchor(mount.id);
      if (!anchor) {
        await delay(250 * (attempt + 1));
        continue;
      }
      await ensureShareParticipantDeviceReady({ requiredShareSlug: anchor.shareSessionKey });
      try {
        const detail = await getShareMount(mount.id);
        if (detail.folder) {
          const workspacePinBootstrap = optionalWorkspacePinBootstrapEnvelope(
            detail.folder.workspace_pin_bootstrap,
          );
          const title = await resolveShareTitle(detail.folder, {
            passwordProtected: mount.password_protected,
            passwordKey: anchor.shareSessionKey,
            fallback: anchor.targetTitle ?? undefined,
            workspaceId: mount.workspace_id,
            workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
            workspacePinBootstrap,
          });
          if (!genericShareTitle(title, mount.target_kind)) return title;
        }
        if (detail.document) {
          const title = await resolveMountedShareTitle(mount.id, detail.document);
          if (!genericShareTitle(title, mount.target_kind)) return title;
        }
      } catch {
        // Retry while the mounted share participant session is being restored.
      }
      if (attempt < 5) {
        await delay(250 * (attempt + 1));
      }
    }
    const anchor = await loadMountTrustAnchor(mount.id);
    return anchor?.targetTitle && !genericShareTitle(anchor.targetTitle, mount.target_kind)
      ? anchor.targetTitle
      : null;
  };

  createEffect(() => {
    const workspaceId = options.workspaceId();
    if (workspaceId !== previousWorkspaceId) {
      previousWorkspaceId = workspaceId;
      clearMountSubtreeMemory();
      setExpandedMountsSignal(new Set<string>());
      setMountEntriesSignal(new Map<string, MountedShareTreeEntry[]>());
      setMountEntryCacheKeysSignal(new Map<string, string>());
      setLoadingMounts(new Set<string>());
      setResolvedMountTitles(new Map<string, string>());
      setPasswordMount(null);
      setMountPassword("");
      setMountPasswordError(null);
    }
  });

  createEffect(() => {
    const activeMountIds = new Set(
      mounts()
        .filter((mount) => mount.status === "active")
        .map((mount) => mount.id),
    );

    setExpandedMounts((current) => {
      const next = new Set([...current].filter((key) => activeMountIds.has(key.split(":")[0])));
      return next.size === current.size ? current : next;
    });

    setMountEntries((current) => {
      const next = new Map(current);
      for (const key of next.keys()) {
        if (!activeMountIds.has(key.split(":")[0])) next.delete(key);
      }
      return next.size === current.size ? current : next;
    });

    setMountEntryCacheKeys((current) => {
      const next = new Map(current);
      for (const key of next.keys()) {
        if (!activeMountIds.has(key.split(":")[0])) next.delete(key);
      }
      return next.size === current.size ? current : next;
    });
  });

  createEffect(() => {
    if (!options.deviceReady()) return;

    const currentMounts = mounts();
    if (currentMounts.length === 0) {
      setResolvedMountTitles(new Map());
      return;
    }

    const known = resolvedMountTitles();
    const unresolved = currentMounts.filter((mount) => !known.has(mount.id));
    if (unresolved.length === 0) return;

    void Promise.allSettled(
      unresolved.map(async (mount) => {
        const title = await resolveMountRootTitle(mount);
        if (!title) return;
        setResolvedMountTitles((current) => {
          if (current.get(mount.id) === title) return current;
          const next = new Map(current);
          next.set(mount.id, title);
          return next;
        });
      }),
    );
  });

  const resolveMountEntryTitles = async (
    mount: ShareMount,
    entries: ShareTreeEntry[],
    workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null,
  ): Promise<MountedShareTreeEntry[]> => {
    const anchor = await loadMountTrustAnchor(mount.id);
    if (!anchor) throw new Error("mount_trust_anchor_unavailable");
    const shareSessionKey = anchor.shareSessionKey;

    return Promise.all(
      entries.map(async (entry) => ({
        ...entry,
        label: await resolveShareTitle(entry, {
          passwordProtected: mount.password_protected,
          passwordKey: shareSessionKey,
          workspaceId: mount.workspace_id,
          workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
          workspacePinBootstrap: optionalWorkspacePinBootstrapEnvelope(
            entry.workspace_pin_bootstrap ?? workspacePinBootstrap,
          ),
        }),
      })),
    );
  };

  const cacheMountRootEntries = async (
    mount: ShareMount,
    folderToken: string,
    entries: ShareTreeEntry[],
    workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null,
  ) => {
    const expansionKey = rootExpansionKey(mount);
    const cacheKey = await currentSubtreeCacheKey(mount, folderToken);
    const resolvedEntries = await resolveMountEntryTitles(mount, entries, workspacePinBootstrap);
    setMountEntries((current) => {
      const next = new Map(current);
      next.set(cacheKey, resolvedEntries);
      return next;
    });
    setMountEntryCacheKeys((current) => {
      const next = new Map(current);
      next.set(expansionKey, cacheKey);
      return next;
    });
    setExpandedMounts((current) => new Set(current).add(expansionKey));
  };

  const closeMountPasswordDialog = (collapseMount: boolean) => {
    const mount = passwordMount();
    if (collapseMount && mount) {
      const key = rootExpansionKey(mount);
      setExpandedMounts((current) => {
        const next = new Set(current);
        next.delete(key);
        return next;
      });
    }
    setPasswordMount(null);
    setMountPassword("");
    setMountPasswordError(null);
  };

  const submitMountPassword = async (event?: Event) => {
    event?.preventDefault();
    const mount = passwordMount();
    if (!mount || submittingMountPassword()) return;

    setSubmittingMountPassword(true);
    setMountPasswordError(null);
    try {
      if (!mount.target_token) throw new Error("mount_target_token_unavailable");
      await respondShareMountPasswordChallenge(mount.id, mountPassword());
      const payload = await getShareMount(mount.id, { allowPasswordBootstrap: true });
      await cacheMountRootEntries(mount, mount.target_token, payload.entries ?? []);
      closeMountPasswordDialog(false);
    } catch (err) {
      const retryMs = getRateLimitRetryMs(err);
      setMountPasswordError(
        retryMs
          ? `Too many attempts. Try again in ${Math.ceil(retryMs / 1000)} seconds.`
          : "Password verification failed.",
      );
    } finally {
      setSubmittingMountPassword(false);
    }
  };

  const openPasswordMountWithStoredSecret = async (mount: ShareMount): Promise<boolean> => {
    try {
      if (!mount.target_token) throw new Error("mount_target_token_unavailable");
      await respondShareMountPasswordChallenge(mount.id);
      const payload = await getShareMount(mount.id, { allowPasswordBootstrap: true });
      await cacheMountRootEntries(mount, mount.target_token, payload.entries ?? []);
      return true;
    } catch {
      return false;
    }
  };

  const currentSubtreeCacheKey = async (
    mount: ShareMount,
    folderToken: string,
  ): Promise<string> => {
    const anchor = await loadMountTrustAnchor(mount.id);
    if (!anchor) throw new Error("mount_trust_anchor_unavailable");
    const session = await ensureShareParticipantDeviceReady({
      requiredShareSlug: anchor.shareSessionKey,
    });
    if (!session) throw new Error("share_participant_session_unavailable");
    return subtreeCacheKey(mount, folderToken, session.redeemAttemptId);
  };

  const toggleMount = async (mount: ShareMount) => {
    if (!mount.target_token) {
      new Notice("Failed to load saved share");
      return;
    }
    const key = rootExpansionKey(mount);
    const expanded = toggleMountKey(key);
    if (!expanded || mountEntryCacheKeys().has(key) || loadingMounts().has(key)) return;

    setMountLoading(key, true);
    try {
      const cacheKey = await currentSubtreeCacheKey(mount, mount.target_token);
      if (mountEntries().has(cacheKey)) {
        setMountEntryCacheKeys((current) => {
          const next = new Map(current);
          next.set(key, cacheKey);
          return next;
        });
        return;
      }
      const detail = await getShareMount(mount.id);
      if (detail.mount.password_protected && !detail.folder) {
        if (!(await openPasswordMountWithStoredSecret(mount))) {
          setPasswordMount(mount);
        }
        return;
      }
      const entries = await resolveMountEntryTitles(mount, detail.entries ?? []);
      setMountEntries((current) => {
        const next = new Map(current);
        next.set(cacheKey, entries);
        return next;
      });
      setMountEntryCacheKeys((current) => {
        const next = new Map(current);
        next.set(key, cacheKey);
        return next;
      });
    } catch {
      new Notice("Failed to load saved share");
    } finally {
      setMountLoading(key, false);
    }
  };

  const toggleMountEntry = async (mount: ShareMount, entry: ShareTreeEntry) => {
    if (!entry.folder_token) return;
    const key = entryExpansionKey(mount, entry);
    const expanded = toggleMountKey(key);
    if (!expanded || mountEntryCacheKeys().has(key) || loadingMounts().has(key)) return;

    setMountLoading(key, true);
    try {
      const cacheKey = await currentSubtreeCacheKey(mount, entry.folder_token);
      if (mountEntries().has(cacheKey)) {
        setMountEntryCacheKeys((current) => {
          const next = new Map(current);
          next.set(key, cacheKey);
          return next;
        });
        return;
      }
      const detail = await getShareMountFolder(mount.id, entry.folder_token);
      const entries = await resolveMountEntryTitles(mount, detail.entries ?? []);
      setMountEntries((current) => {
        const next = new Map(current);
        next.set(cacheKey, entries);
        return next;
      });
      setMountEntryCacheKeys((current) => {
        const next = new Map(current);
        next.set(key, cacheKey);
        return next;
      });
    } catch {
      new Notice("Failed to load saved share folder");
    } finally {
      setMountLoading(key, false);
    }
  };

  const unmount = async (mount: ShareMount) => {
    if (!window.confirm('Unmount "saved share"?')) return;
    try {
      await deleteShareMount(mount.id);
      setExpandedMounts((current) => {
        const next = new Set(
          [...current].filter((key) => key !== mount.id && !key.startsWith(`${mount.id}:`)),
        );
        return next;
      });
      setMountEntries((current) => {
        const next = new Map(current);
        for (const key of next.keys()) {
          if (key === mount.id || key.startsWith(`${mount.id}:`)) next.delete(key);
        }
        return next;
      });
      setMountEntryCacheKeys((current) => {
        const next = new Map(current);
        for (const key of next.keys()) {
          if (key === mount.id || key.startsWith(`${mount.id}:`)) next.delete(key);
        }
        return next;
      });
      await mountsQuery.refetch();
    } catch {
      new Notice("Failed to unmount saved share");
    }
  };

  return {
    mountsQuery,
    resolvedMounts,
    passwordMount,
    setPasswordMount,
    mountPassword,
    setMountPassword,
    mountPasswordError,
    submittingMountPassword,
    closeMountPasswordDialog,
    submitMountPassword,
    isMountExpanded: (key: string) => expandedMounts().has(key),
    isMountLoading: (key: string) => loadingMounts().has(key),
    getMountEntries: (key: string) => {
      const cacheKey = mountEntryCacheKeys().get(key);
      return cacheKey ? (mountEntries().get(cacheKey) ?? []) : [];
    },
    toggleMount,
    toggleMountEntry,
    unmount,
  };
}
