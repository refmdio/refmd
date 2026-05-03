import { createMemo, createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { offlineMode } from "@/shared/lib/offline/offline-state";
import { Notice } from "@/shared/lib/notice";
import { FilePlusIcon, FolderPlusIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { DocumentTree } from "./DocumentTree";
import { DocumentContextMenu } from "./DocumentContextMenu";
import { ArchiveSection } from "./ArchiveSection";
import {
  useDocuments,
  useDocumentTitles,
  useExpandedFolders,
  selectedDocumentId,
  type DragSibling,
} from "@/entities/document";
import {
  deleteShareMount,
  getShareMount,
  getShareMountFolder,
  useShareMounts,
} from "@/entities/mount";
import { currentWorkspaceId } from "@/entities/workspace";
import { getRateLimitRetryMs } from "@/shared/api";
import { CreateDocumentDialog, CreateFolderDialog } from "@/features/document";
import { activateSharedDocumentRoute } from "@/features/editor";
import {
  createMountedShareDocumentPanelTarget,
  decodePanelId,
  usePanelWorkspace,
} from "@/features/panel";
import {
  mountPasswordKey,
  resolveMountedShareOpen,
  resolveShareTitle,
  respondShareMountPasswordChallenge,
} from "@/features/share";
import { useSidebarDocumentTreeHandlers } from "../model/useSidebarDocumentTreeHandlers";
import { useDocumentSharePermissions } from "@/features/workspace";
import { buildSidebarDragSiblings } from "../model/drag-siblings";
import { buildSidebarRows } from "../model/rows";
import type {
  MountedShareTreeEntry,
  ShareMount,
  ShareMountAdmission,
  ShareMountDetail,
  ShareTreeEntry,
} from "@/entities/mount";
import { authState, deviceState } from "@/entities/session";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Field, FieldDescription, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";

function treeKey(mountId: string, folderId: string): string {
  return `${mountId}:${folderId}`;
}

export function DocumentTreePanel() {
  const navigate = useNavigate();
  const workspaceId = () => currentWorkspaceId();
  const panelWorkspace = usePanelWorkspace();
  const sharePermissions = useDocumentSharePermissions(workspaceId);
  const { flatDocuments, query } = useDocuments(workspaceId);
  const { query: mountsQuery, mounts } = useShareMounts(workspaceId);
  const { getTitle, isTitleReady } = useDocumentTitles(flatDocuments, workspaceId);
  const { isExpanded, toggle, expand } = useExpandedFolders(workspaceId);
  const [expandedMounts, setExpandedMounts] = createSignal(new Set<string>());
  const [loadingMounts, setLoadingMounts] = createSignal(new Set<string>());
  const [mountEntries, setMountEntries] = createSignal(new Map<string, MountedShareTreeEntry[]>());
  const [passwordMount, setPasswordMount] = createSignal<ShareMount | null>(null);
  const [mountPassword, setMountPassword] = createSignal("");
  const [mountPasswordError, setMountPasswordError] = createSignal<string | null>(null);
  const [submittingMountPassword, setSubmittingMountPassword] = createSignal(false);

  const activeDocuments = () => flatDocuments().filter((d) => !d.archived_at);
  const getDragSiblings = (parentId: string | null, excludedDocumentId: string): DragSibling[] =>
    buildSidebarDragSiblings(flatDocuments(), mounts(), parentId, excludedDocumentId);
  const sidebarTree = createMemo(() => buildSidebarRows(activeDocuments(), mounts()));
  const selectedMountKey = () => {
    const panelId = panelWorkspace.focusedPanelId();
    if (!panelId) return null;
    const panel = decodePanelId(panelId);
    if (panel?.source !== "mounted-share-document") return null;
    const [, mountId, shareId] = panel.targetKey.split(":");
    if (!mountId || !shareId) return null;
    return `mount:${mountId}:${shareId}`;
  };

  const [createDocOpen, setCreateDocOpen] = createSignal(false);
  const [createFolderOpen, setCreateFolderOpen] = createSignal(false);

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

  const closeMountPasswordDialog = (collapseMount: boolean) => {
    const mount = passwordMount();
    if (collapseMount && mount) {
      const key = treeKey(mount.id, mount.target_document_id);
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

  const toggleMount = async (mount: ShareMount) => {
    const key = treeKey(mount.id, mount.target_document_id);
    const expanded = toggleMountKey(key);
    if (!expanded || mountEntries().has(key) || loadingMounts().has(key)) return;

    if (mount.password_protected) {
      setPasswordMount(mount);
      setMountPassword("");
      setMountPasswordError(null);
      return;
    }

    setMountLoading(key, true);
    try {
      const detail = await getShareMount(mount.id);
      const entries = await resolveMountEntryTitles(mount, detail.folder_tree?.entries ?? []);
      setMountEntries((current) => {
        const next = new Map(current);
        next.set(key, entries);
        return next;
      });
    } catch {
      new Notice("Failed to load saved share");
    } finally {
      setMountLoading(key, false);
    }
  };

  const cacheMountRootEntries = async (mount: ShareMount, entries: ShareTreeEntry[]) => {
    const key = treeKey(mount.id, mount.target_document_id);
    const resolvedEntries = await resolveMountEntryTitles(mount, entries);
    setMountEntries((current) => {
      const next = new Map(current);
      next.set(key, resolvedEntries);
      return next;
    });
    setExpandedMounts((current) => new Set(current).add(key));
  };

  const handleMountPasswordSubmit = async (event: Event) => {
    event.preventDefault();
    const mount = passwordMount();
    if (!mount || submittingMountPassword()) return;

    setSubmittingMountPassword(true);
    setMountPasswordError(null);
    try {
      const result = await respondShareMountPasswordChallenge(mount.id, mountPassword());
      const payload = result as { folder_tree?: { entries?: ShareTreeEntry[] } };
      await cacheMountRootEntries(mount, payload.folder_tree?.entries ?? []);
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

  const toggleMountEntry = async (mount: ShareMount, entry: ShareTreeEntry) => {
    if (!entry.folder_token) return;
    const key = treeKey(mount.id, entry.id);
    const expanded = toggleMountKey(key);
    if (!expanded || mountEntries().has(key) || loadingMounts().has(key)) return;

    setMountLoading(key, true);
    try {
      const detail = await getShareMountFolder(mount.id, entry.folder_token);
      const entries = await resolveMountEntryTitles(mount, detail.entries ?? []);
      setMountEntries((current) => {
        const next = new Map(current);
        next.set(key, entries);
        return next;
      });
    } catch {
      new Notice("Failed to load saved share folder");
    } finally {
      setMountLoading(key, false);
    }
  };

  const resolveMountEntryTitles = async (
    mount: ShareMount,
    entries: ShareTreeEntry[],
  ): Promise<MountedShareTreeEntry[]> =>
    Promise.all(
      entries.map(async (entry) => ({
        ...entry,
        label: await resolveShareTitle(entry, {
          passwordProtected: mount.password_protected,
          passwordKey: mountPasswordKey(mount.id),
        }),
      })),
    );

  const openMountedAdmission = async (
    mountId: string,
    detail: ShareMountDetail,
    admission: ShareMountAdmission,
    mode: "replace" | "tile",
  ) => {
    const auth = authState();
    const device = deviceState();
    if (!auth || !device?.deviceSigningPublic || !device.deviceEcdhPublic) {
      new Notice("Device keys are not ready. Please reload and try again.");
      return;
    }

    const opened = await resolveMountedShareOpen(mountId, detail, admission, {
      principalId: auth.user.id,
      displayName: auth.user.name,
      deviceId: device.deviceId,
      signingPublicKey: device.deviceSigningPublic,
      encryptionPublicKey: device.deviceEcdhPublic,
    });
    const isRootDocument = admission.document_id === detail.mount.target_document_id;
    const target = createMountedShareDocumentPanelTarget({
      mountId,
      shareId: admission.share_id,
      documentId: admission.document_id,
      title: opened.title,
      workspaceId: detail.mount.workspace_id,
      routePath: isRootDocument
        ? `/mounts/${mountId}`
        : `/mounts/${mountId}?share=${admission.share_id}`,
    });

    activateSharedDocumentRoute(target.targetKey, opened.access);

    if (mode === "tile") {
      panelWorkspace.addToTile(target);
    } else {
      panelWorkspace.openDocument(target);
    }
  };

  const openMountedDocument = async (
    mount: ShareMount,
    mode: "replace" | "tile",
    shareId?: string | null,
  ) => {
    if (mount.status !== "active") {
      new Notice("This saved share is no longer available");
      return;
    }

    try {
      const detail = await getShareMount(mount.id, { shareId });
      if (!detail.admission) {
        if (detail.mount.password_protected) {
          navigate(shareId ? `/mounts/${mount.id}?share=${shareId}` : `/mounts/${mount.id}`, {
            scroll: false,
          });
          return;
        }
        new Notice("This saved share cannot be opened.");
        return;
      }

      await openMountedAdmission(mount.id, detail, detail.admission, mode);
    } catch {
      new Notice("Saved share not found or access denied.");
    }
  };

  const openMount = (mount: ShareMount) => {
    if (mount.status !== "active") {
      new Notice("This saved share is no longer available");
      return;
    }
    if (mount.target_kind === "folder") {
      void toggleMount(mount);
      return;
    }
    void openMountedDocument(mount, "replace");
  };

  const addMountToTile = (mount: ShareMount) => {
    if (mount.target_kind === "folder") return;
    void openMountedDocument(mount, "tile");
  };

  const openMountEntry = (mount: ShareMount, entry: ShareTreeEntry) => {
    if (entry.doc_type === "folder") {
      void toggleMountEntry(mount, entry);
      return;
    }
    void openMountedDocument(mount, "replace", entry.share_id);
  };

  const addMountEntryToTile = (mount: ShareMount, entry: ShareTreeEntry) => {
    if (entry.doc_type === "folder") return;
    void openMountedDocument(mount, "tile", entry.share_id);
  };

  const unmount = async (mount: ShareMount) => {
    if (!window.confirm(`Unmount "${mount.title ?? mount.target.title ?? "saved share"}"?`)) return;
    try {
      await deleteShareMount(mount.id);
      setExpandedMounts((current) => {
        const next = new Set([...current].filter((key) => !key.startsWith(`${mount.id}:`)));
        return next;
      });
      setMountEntries((current) => {
        const next = new Map(current);
        for (const key of next.keys()) {
          if (key.startsWith(`${mount.id}:`)) next.delete(key);
        }
        return next;
      });
      await mountsQuery.refetch();
    } catch {
      new Notice("Failed to unmount saved share");
    }
  };

  const isArchivedFolder = (docId: string | null): boolean => {
    if (!docId) return false;
    const doc = flatDocuments().find((d) => d.id === docId);
    return !!doc && doc.doc_type === "folder" && doc.archived_at != null;
  };

  const isSelectedInArchivedFolder = (): boolean => {
    const selId = selectedDocumentId();
    if (!selId) return false;
    const docs = flatDocuments();
    const sel = docs.find((d) => d.id === selId);
    if (!sel) return false;
    if (sel.doc_type !== "folder") return false;
    return isArchivedFolder(sel.id);
  };

  const selectedParentId = (): string | null => {
    const selId = selectedDocumentId();
    if (!selId) return null;
    const docs = flatDocuments();
    const sel = docs.find((d) => d.id === selId);
    if (!sel || sel.doc_type !== "folder") return null;
    if (isArchivedFolder(sel.id)) return null;
    return sel.id;
  };

  const {
    drag,
    selectedId,
    contextTarget,
    handleSelect,
    handleContextMenu,
    closeContextMenu,
    handleAddToTile,
    handleCreateDocument,
    handleCreateFolder,
    handleRename,
    handleMove,
    handleArchive,
    handleUnarchive,
    handleDelete,
    folders,
  } = useSidebarDocumentTreeHandlers({
    workspaceId,
    flatDocuments,
    getTitle,
    isTitleReady,
    expand,
    selectedParentId,
    isOffline: offlineMode,
    getDragSiblings,
    onDragDropError: () => {
      new Notice("Failed to reorder document");
    },
  });

  return (
    <>
      <Show when={workspaceId()}>
        <div class="px-2 py-1 border-b border-border flex items-center justify-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            class="size-7"
            onClick={() => setCreateDocOpen(true)}
            disabled={isSelectedInArchivedFolder()}
            title="New Document"
          >
            <FilePlusIcon class="size-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            class="size-7"
            onClick={() => setCreateFolderOpen(true)}
            disabled={isSelectedInArchivedFolder() || offlineMode()}
            title="New Folder"
          >
            <FolderPlusIcon class="size-4" />
          </Button>
        </div>
      </Show>

      <div class="flex-1 overflow-hidden flex flex-col">
        <Show
          when={workspaceId()}
          fallback={
            <div class="flex-1 flex items-center justify-center">
              <p class="text-xs text-muted-foreground">No workspace selected</p>
            </div>
          }
        >
          <DocumentContextMenu
            targetDoc={contextTarget()}
            onClose={closeContextMenu}
            getTitle={getTitle}
            isTitleReady={isTitleReady}
            folders={folders()}
            documents={flatDocuments()}
            onRename={handleRename}
            onMove={handleMove}
            onAddToTile={handleAddToTile}
            onArchive={handleArchive}
            onUnarchive={handleUnarchive}
            onDelete={handleDelete}
            canManageShares={sharePermissions.canManageShares()}
            canDeleteShares={sharePermissions.canDeleteShares()}
            canPublishPublic={sharePermissions.canPublishPublic()}
            setError={(message) => {
              if (message) new Notice(message);
            }}
          >
            <div class="flex-1 overflow-y-auto">
              <DocumentTree
                tree={sidebarTree()}
                isLoading={query.isLoading || mountsQuery.isLoading}
                isError={query.isError || mountsQuery.isError}
                refetch={() => {
                  void query.refetch();
                  void mountsQuery.refetch();
                }}
                isExpanded={isExpanded}
                onToggle={toggle}
                selectedId={selectedId()}
                selectedMountKey={selectedMountKey()}
                onSelect={handleSelect}
                getTitle={getTitle}
                isTitleReady={isTitleReady}
                onContextMenu={handleContextMenu}
                draggedId={drag.draggedId()}
                dropTarget={drag.dropTarget()}
                onDragStart={drag.handleDragStart}
                onDragOver={drag.handleDragOver}
                onDragLeave={drag.handleDragLeave}
                onDrop={drag.handleDrop}
                onDragEnd={drag.handleDragEnd}
                onRootDragOver={drag.handleRootDragOver}
                onRootDrop={drag.handleRootDrop}
                isMountExpanded={(key) => expandedMounts().has(key)}
                isMountLoading={(key) => loadingMounts().has(key)}
                getMountEntries={(key) => mountEntries().get(key) ?? []}
                onMountToggle={(mount) => void toggleMount(mount)}
                onMountEntryToggle={(mount, entry) => void toggleMountEntry(mount, entry)}
                onMountOpen={openMount}
                onMountAddToTile={addMountToTile}
                onMountEntryOpen={openMountEntry}
                onMountEntryAddToTile={addMountEntryToTile}
                onMountUnmount={(mount) => void unmount(mount)}
              />
            </div>
          </DocumentContextMenu>
        </Show>
      </div>

      <div class="mt-auto shrink-0">
        <ArchiveSection />
      </div>

      <CreateDocumentDialog
        open={createDocOpen()}
        onOpenChange={setCreateDocOpen}
        onSubmit={handleCreateDocument!}
      />

      <CreateFolderDialog
        open={createFolderOpen()}
        onOpenChange={setCreateFolderOpen}
        onSubmit={handleCreateFolder!}
      />

      <Dialog
        open={!!passwordMount()}
        onOpenChange={(open) => {
          if (open || submittingMountPassword()) return;
          closeMountPasswordDialog(true);
        }}
      >
        <DialogContent class="max-w-md">
          <form class="space-y-4" onSubmit={handleMountPasswordSubmit}>
            <DialogHeader>
              <DialogTitle>Unlock Saved Share</DialogTitle>
              <DialogDescription>
                Enter the password before expanding this saved folder share.
              </DialogDescription>
            </DialogHeader>

            <Field>
              <FieldLabel for="sidebar-mount-password">Password</FieldLabel>
              <Input
                id="sidebar-mount-password"
                type="password"
                value={mountPassword()}
                onInput={(event) => setMountPassword(event.currentTarget.value)}
                autocomplete="current-password"
                required
                disabled={submittingMountPassword()}
              />
              <FieldDescription>
                {passwordMount()?.title ?? passwordMount()?.target.title ?? "Saved share"}
              </FieldDescription>
            </Field>

            <Show when={mountPasswordError()}>
              {(message) => <p class="text-sm text-destructive">{message()}</p>}
            </Show>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={submittingMountPassword()}
                onClick={() => closeMountPasswordDialog(true)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={submittingMountPassword() || mountPassword().length === 0}
              >
                {submittingMountPassword() ? "Unlocking..." : "Unlock"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
