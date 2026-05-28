import { createSignal, For, onCleanup, Show, type ParentProps } from "solid-js";
import {
  PencilIcon,
  MoveIcon,
  PanelRightIcon,
  Share2Icon,
  ArchiveIcon,
  ArchiveRestoreIcon,
  Globe2Icon,
  TrashIcon,
} from "lucide-solid";
import type { DocumentResponse } from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { RenameDialog, DeleteConfirmDialog, MoveDialog } from "@/features/document";
import { PublishDialog } from "@/features/publication";
import { ShareManagementDialog } from "@/features/share";
import { useWorkspaceQuery } from "@/features/workspace";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/shared/ui/context-menu";
import {
  getDefaultPluginUiContributionRegistry,
  pluginUiCommandId,
  pluginUiCommandResourcePayload,
  pluginUiEntryCommandEnabled,
  type PluginUiRegistryEntry,
  type PluginUiResourceContext,
} from "@/features/plugin-runtime";
import { workspaceManager } from "@/features/panel";

interface DocumentContextMenuProps {
  targetDoc: DocumentResponse | null;
  onClose: () => void;
  getTitle: (doc: DocumentResponse) => string;
  folders: DocumentResponse[];
  documents: DocumentResponse[];
  onRename: (doc: DocumentResponse, newTitle: string) => Promise<void>;
  onMove: (doc: DocumentResponse, parentId: string | null) => Promise<void>;
  isTitleReady: (doc: DocumentResponse) => boolean;
  onAddToTile: (doc: DocumentResponse) => void;
  onArchive: (doc: DocumentResponse) => Promise<void>;
  onUnarchive: (doc: DocumentResponse) => Promise<void>;
  onDelete: (doc: DocumentResponse) => Promise<void>;
  canManageShares: boolean;
  canDeleteShares: boolean;
  canPublishPublic: boolean;
  setError: (value: string | null) => void;
}

export function DocumentContextMenu(props: ParentProps<DocumentContextMenuProps>) {
  const [registryVersion, setRegistryVersion] = createSignal(0);
  const uiRegistry = getDefaultPluginUiContributionRegistry();
  const unsubscribe = uiRegistry.subscribe(() => setRegistryVersion((value) => value + 1));
  onCleanup(unsubscribe);
  const [renameOpen, setRenameOpen] = createSignal(false);
  const [moveOpen, setMoveOpen] = createSignal(false);
  const [deleteOpen, setDeleteOpen] = createSignal(false);
  const [shareOpen, setShareOpen] = createSignal(false);
  const [publishOpen, setPublishOpen] = createSignal(false);
  const [dialogDoc, setDialogDoc] = createSignal<DocumentResponse | null>(null);
  const workspace = useWorkspaceQuery(currentWorkspaceId);

  const doc = () => props.targetDoc;
  const resourceContext = (entry: PluginUiRegistryEntry): PluginUiResourceContext => ({
    resourceKind: doc()?.doc_type === "folder" ? "folder" : doc() ? "document" : "workspace",
    workspaceId: doc()?.workspace_id ?? currentWorkspaceId() ?? undefined,
    documentId: doc()?.doc_type === "document" ? doc()?.id : undefined,
    folderId: doc()?.doc_type === "folder" ? doc()?.id : undefined,
    documentOpen: doc()?.doc_type === "document",
    selectionPresent: false,
    capabilities: entry.capabilities,
  });
  const isArchived = () => doc()?.archived_at != null;
  const canShare = () => props.canManageShares && workspace.data?.share_links_enabled === true;
  const canPublish = () =>
    props.canPublishPublic &&
    doc()?.doc_type === "document" &&
    workspace.data?.public_publishing_enabled === true;
  const pluginMenuItems = () => {
    registryVersion();
    return uiRegistry
      .list("menu_item")
      .filter(
        (entry) =>
          entry.contribution.surface === "menu_item" &&
          entry.contribution.placement === "document_tree_context_menu" &&
          pluginUiEntryCommandEnabled(entry, resourceContext(entry), uiRegistry),
      );
  };
  const pluginDocumentTreeActions = () => {
    registryVersion();
    return uiRegistry
      .list("document_tree_action")
      .filter(
        (entry) =>
          entry.contribution.surface === "document_tree_action" &&
          entry.contribution.placement === "row_context_menu" &&
          pluginUiEntryCommandEnabled(entry, resourceContext(entry), uiRegistry),
      );
  };

  const openRename = () => {
    setDialogDoc(doc());
    setRenameOpen(true);
    props.onClose();
  };

  const openMove = () => {
    setDialogDoc(doc());
    setMoveOpen(true);
    props.onClose();
  };

  const openDelete = () => {
    setDialogDoc(doc());
    setDeleteOpen(true);
    props.onClose();
  };

  const openShare = () => {
    setDialogDoc(doc());
    setShareOpen(true);
    props.onClose();
  };

  const openPublish = () => {
    setDialogDoc(doc());
    setPublishOpen(true);
    props.onClose();
  };

  return (
    <>
      <ContextMenu
        modal={false}
        onOpenChange={(open: boolean) => {
          if (!open) props.onClose();
        }}
      >
        <ContextMenuTrigger class="contents">{props.children}</ContextMenuTrigger>
        <Show when={doc()}>
          <ContextMenuContent
            onEscapeKeyDown={props.onClose}
            onPointerDownOutside={props.onClose}
            onFocusOutside={props.onClose}
            onInteractOutside={props.onClose}
          >
            <Show when={doc()?.doc_type === "document" && props.isTitleReady(doc()!)}>
              <ContextMenuItem
                onSelect={() => {
                  props.onAddToTile(doc()!);
                  props.onClose();
                }}
              >
                <PanelRightIcon class="size-3.5" />
                Add to Tile
              </ContextMenuItem>
            </Show>
            <Show when={!isArchived()}>
              <ContextMenuItem onSelect={openRename}>
                <PencilIcon class="size-3.5" />
                Rename
              </ContextMenuItem>
              <ContextMenuItem onSelect={openMove}>
                <MoveIcon class="size-3.5" />
                Move
              </ContextMenuItem>
              <Show when={canShare()}>
                <ContextMenuItem onSelect={openShare}>
                  <Share2Icon class="size-3.5" />
                  Share
                </ContextMenuItem>
              </Show>
              <Show when={canPublish()}>
                <ContextMenuItem onSelect={openPublish}>
                  <Globe2Icon class="size-3.5" />
                  Publish
                </ContextMenuItem>
              </Show>
            </Show>
            <Show when={!isArchived()}>
              <ContextMenuItem
                onSelect={() => {
                  void props.onArchive(doc()!);
                  props.onClose();
                }}
              >
                <ArchiveIcon class="size-3.5" />
                Archive
              </ContextMenuItem>
            </Show>
            <Show when={isArchived()}>
              <ContextMenuItem
                onSelect={() => {
                  void props.onUnarchive(doc()!);
                  props.onClose();
                }}
              >
                <ArchiveRestoreIcon class="size-3.5" />
                Unarchive
              </ContextMenuItem>
            </Show>
            <For each={pluginMenuItems()}>
              {(entry) => (
                <ContextMenuItem
                  onSelect={() => {
                    runPluginMenuCommand(entry, resourceContext(entry), uiRegistry);
                    props.onClose();
                  }}
                >
                  {pluginMenuTitle(entry)}
                </ContextMenuItem>
              )}
            </For>
            <For each={pluginDocumentTreeActions()}>
              {(entry) => (
                <ContextMenuItem
                  onSelect={() => {
                    runPluginDocumentTreeAction(entry, resourceContext(entry), uiRegistry);
                    props.onClose();
                  }}
                >
                  {pluginDocumentTreeActionTitle(entry)}
                </ContextMenuItem>
              )}
            </For>
            <ContextMenuSeparator />
            <ContextMenuItem variant="destructive" onSelect={openDelete}>
              <TrashIcon class="size-3.5" />
              Delete
            </ContextMenuItem>
          </ContextMenuContent>
        </Show>
      </ContextMenu>
      <Show when={dialogDoc()}>
        <RenameDialog
          open={renameOpen()}
          onOpenChange={setRenameOpen}
          currentTitle={props.getTitle(dialogDoc()!)}
          onSubmit={(newTitle) => props.onRename(dialogDoc()!, newTitle)}
        />
        <MoveDialog
          open={moveOpen()}
          onOpenChange={setMoveOpen}
          document={dialogDoc()!}
          folders={props.folders}
          getTitle={props.getTitle}
          onSubmit={(parentId) => props.onMove(dialogDoc()!, parentId)}
        />
        <DeleteConfirmDialog
          open={deleteOpen()}
          onOpenChange={setDeleteOpen}
          title={props.getTitle(dialogDoc()!)}
          isFolder={dialogDoc()!.doc_type === "folder"}
          onConfirm={() => props.onDelete(dialogDoc()!)}
        />
        <ShareManagementDialog
          open={shareOpen()}
          onOpenChange={setShareOpen}
          document={dialogDoc()}
          documents={props.documents}
          canDeleteShares={props.canDeleteShares}
          getTitle={props.getTitle}
          title={props.getTitle(dialogDoc()!)}
          setError={props.setError}
        />
        <PublishDialog
          open={publishOpen()}
          onOpenChange={setPublishOpen}
          document={dialogDoc()}
          title={props.getTitle(dialogDoc()!)}
          canPublishPublic={props.canPublishPublic}
          setError={props.setError}
        />
      </Show>
    </>
  );
}

function pluginMenuTitle(entry: PluginUiRegistryEntry): string {
  const contribution = entry.contribution;
  return contribution.surface === "menu_item" ? contribution.title : "";
}

function pluginDocumentTreeActionTitle(entry: PluginUiRegistryEntry): string {
  const contribution = entry.contribution;
  return contribution.surface === "document_tree_action"
    ? (contribution.icon ?? contribution.title)
    : "";
}

function runPluginMenuCommand(
  entry: PluginUiRegistryEntry,
  context: PluginUiResourceContext,
  registry: ReturnType<typeof getDefaultPluginUiContributionRegistry>,
): void {
  const contribution = entry.contribution;
  if (contribution.surface !== "menu_item") return;
  const payload = pluginUiCommandResourcePayload(entry, context, registry);
  if (!payload) return;
  const commandId = pluginUiCommandId(entry, contribution.command_ref);
  workspaceManager
    .listCommands()
    .find((command) => command.id === commandId)
    ?.callback?.(payload);
}

function runPluginDocumentTreeAction(
  entry: PluginUiRegistryEntry,
  context: PluginUiResourceContext,
  registry: ReturnType<typeof getDefaultPluginUiContributionRegistry>,
): void {
  const contribution = entry.contribution;
  if (contribution.surface !== "document_tree_action") return;
  const payload = pluginUiCommandResourcePayload(entry, context, registry);
  if (!payload) return;
  const commandId = pluginUiCommandId(entry, contribution.command_ref);
  workspaceManager
    .listCommands()
    .find((command) => command.id === commandId)
    ?.callback?.(payload);
}
