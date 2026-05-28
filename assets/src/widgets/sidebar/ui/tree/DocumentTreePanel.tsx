import { createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import { offlineMode } from "@/shared/lib/offline/offline-state";
import { Notice } from "@/shared/lib/notice";
import { FilePlusIcon, FolderPlusIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { DocumentTree } from "./DocumentTree";
import { DocumentContextMenu } from "../menu/DocumentContextMenu";
import { ArchiveSection } from "../archive/ArchiveSection";
import {
  useDocuments,
  useDocumentTitles,
  useExpandedFolders,
  selectedDocumentId,
} from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { CreateDocumentDialog, CreateFolderDialog } from "@/features/document";
import { decodePanelId, usePanelWorkspace, workspaceManager } from "@/features/panel";
import { useShareMountTree } from "@/features/share";
import { useDocumentSharePermissions } from "@/features/workspace";
import { useSidebarDocumentTreeHandlers } from "../../model/tree/use-document-tree-handlers";
import { useSidebarMountedShareOpen } from "../../model/mount/use-mounted-share-open";
import { buildSidebarRows } from "../../model/tree/rows";
import { deviceState } from "@/entities/session";
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
import {
  getDefaultPluginUiContributionRegistry,
  pluginUiCommandId,
  pluginUiCommandResourcePayload,
  pluginUiEntryCommandEnabled,
  pluginUiEntryMatchesResource,
  type PluginUiRegistryEntry,
  type PluginUiResourceContext,
} from "@/features/plugin-runtime";

const uiRegistry = getDefaultPluginUiContributionRegistry();

export function DocumentTreePanel() {
  const registryEntries = useUiRegistryEntries();
  const workspaceId = () => currentWorkspaceId();
  const panelWorkspace = usePanelWorkspace();
  const mountedShareOpen = useSidebarMountedShareOpen();
  const sharePermissions = useDocumentSharePermissions(workspaceId);
  const { flatDocuments, query } = useDocuments(workspaceId);
  const { getTitle, isTitleReady } = useDocumentTitles(flatDocuments, workspaceId);
  const { isExpanded, toggle, expand } = useExpandedFolders(workspaceId);
  const shareMountTree = useShareMountTree({
    workspaceId,
    deviceReady: () => Boolean(deviceState()),
  });

  const activeDocuments = () => flatDocuments().filter((d) => !d.archived_at);
  const sidebarTree = createMemo(() =>
    buildSidebarRows(activeDocuments(), shareMountTree.resolvedMounts()),
  );
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
    shareMounts: shareMountTree.resolvedMounts,
    onDragDropError: () => {
      new Notice("Failed to reorder item");
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
              <For each={virtualSections(registryEntries, "before_tree")}>
                {(entry) => <VirtualSectionButton entry={entry} />}
              </For>
              <DocumentTree
                tree={sidebarTree()}
                isLoading={query.isLoading || shareMountTree.mountsQuery.isLoading}
                isError={query.isError || shareMountTree.mountsQuery.isError}
                refetch={() => {
                  void query.refetch();
                  void shareMountTree.mountsQuery.refetch();
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
                isMountExpanded={shareMountTree.isMountExpanded}
                isMountLoading={shareMountTree.isMountLoading}
                getMountEntries={shareMountTree.getMountEntries}
                onMountToggle={(mount) => void shareMountTree.toggleMount(mount)}
                onMountEntryToggle={(mount, entry) =>
                  void shareMountTree.toggleMountEntry(mount, entry)
                }
                onMountOpen={(mount) =>
                  mountedShareOpen.openMount(
                    mount,
                    (target) => void shareMountTree.toggleMount(target),
                  )
                }
                onMountAddToTile={mountedShareOpen.addMountToTile}
                onMountEntryOpen={(mount, entry) =>
                  mountedShareOpen.openMountEntry(
                    mount,
                    entry,
                    (targetMount, targetEntry) =>
                      void shareMountTree.toggleMountEntry(targetMount, targetEntry),
                  )
                }
                onMountEntryAddToTile={mountedShareOpen.addMountEntryToTile}
                onMountUnmount={(mount) => void shareMountTree.unmount(mount)}
              />
              <For each={virtualSections(registryEntries, "after_tree")}>
                {(entry) => <VirtualSectionButton entry={entry} />}
              </For>
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
        open={!!shareMountTree.passwordMount()}
        onOpenChange={(open) => {
          if (open || shareMountTree.submittingMountPassword()) return;
          shareMountTree.closeMountPasswordDialog(true);
        }}
      >
        <DialogContent class="max-w-md">
          <form class="space-y-4" onSubmit={shareMountTree.submitMountPassword}>
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
                value={shareMountTree.mountPassword()}
                onInput={(event) => shareMountTree.setMountPassword(event.currentTarget.value)}
                autocomplete="current-password"
                required
                disabled={shareMountTree.submittingMountPassword()}
              />
              <FieldDescription>Saved share</FieldDescription>
            </Field>

            <Show when={shareMountTree.mountPasswordError()}>
              {(message) => <p class="text-sm text-destructive">{message()}</p>}
            </Show>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={shareMountTree.submittingMountPassword()}
                onClick={() => shareMountTree.closeMountPasswordDialog(true)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={
                  shareMountTree.submittingMountPassword() ||
                  shareMountTree.mountPassword().length === 0
                }
              >
                {shareMountTree.submittingMountPassword() ? "Unlocking..." : "Unlock"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

function useUiRegistryEntries() {
  const [version, setVersion] = createSignal(0);
  const unsubscribe = uiRegistry.subscribe(() => setVersion((value) => value + 1));
  onCleanup(unsubscribe);
  return (surface: Parameters<typeof uiRegistry.list>[0]) => {
    version();
    return uiRegistry.list(surface);
  };
}

function virtualSections(
  registryEntries: ReturnType<typeof useUiRegistryEntries>,
  placement: "before_tree" | "after_tree",
): PluginUiRegistryEntry[] {
  return registryEntries("document_tree_virtual_section").filter(
    (entry) =>
      entry.contribution.surface === "document_tree_virtual_section" &&
      entry.contribution.placement === placement &&
      pluginUiEntryMatchesResource(entry, virtualSectionContext(entry)),
  );
}

function virtualSectionContext(entry: PluginUiRegistryEntry): PluginUiResourceContext {
  return {
    resourceKind: "workspace",
    workspaceId: currentWorkspaceId() ?? undefined,
    documentOpen: selectedDocumentId() !== null,
    selectionPresent: false,
    capabilities: entry.capabilities,
  };
}

function VirtualSectionButton(props: { entry: PluginUiRegistryEntry }) {
  const contribution = () => props.entry.contribution;
  const title = () => {
    const current = contribution();
    return current.surface === "document_tree_virtual_section" ? current.title : "";
  };
  const run = () => {
    const current = contribution();
    if (current.surface !== "document_tree_virtual_section") return;
    const context = virtualSectionContext(props.entry);
    if (!pluginUiEntryCommandEnabled(props.entry, context, uiRegistry)) return;
    const payload = pluginUiCommandResourcePayload(props.entry, context, uiRegistry);
    if (!payload) return;
    const commandId = pluginUiCommandId(props.entry, current.source_command_ref);
    const command = workspaceManager.listCommands().find((item) => item.id === commandId);
    command?.callback?.(payload);
  };

  return (
    <button
      type="button"
      class="mx-2 my-1 flex w-[calc(100%-1rem)] items-center rounded px-2 py-1 text-left text-xs text-sidebar-foreground/70 hover:bg-sidebar-accent"
      onClick={run}
    >
      <span class="truncate">{title()}</span>
    </button>
  );
}
