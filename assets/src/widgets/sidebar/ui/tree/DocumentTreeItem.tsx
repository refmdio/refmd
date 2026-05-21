import { Show, For } from "solid-js";
import {
  ChevronRightIcon,
  ChevronDownIcon,
  FolderIcon,
  FileTextIcon,
  LinkIcon,
  PanelRightIcon,
  TrashIcon,
  LockIcon,
} from "lucide-solid";
import type { DocumentResponse } from "@/entities/document";
import type {
  MountedShareTreeEntry,
  ResolvedShareMount,
  ShareMount,
  ShareTreeEntry,
} from "@/entities/mount";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/shared/ui/context-menu";
import { Spinner } from "@/shared/ui/spinner";
import { buildMountChildRows, type SidebarTreeNode } from "../../model/tree/rows";
import type { SidebarDragTarget, SidebarDropTarget } from "../../model/tree/use-tree-drag";

interface DocumentTreeItemProps {
  node: SidebarTreeNode;
  isExpanded: (id: string) => boolean;
  onToggle: (id: string) => void;
  selectedId: string | null;
  selectedMountKey: string | null;
  onSelect: (id: string) => void;
  getTitle: (doc: DocumentResponse) => string;
  isTitleReady: (doc: DocumentResponse) => boolean;
  onContextMenu: (e: MouseEvent, doc: DocumentResponse) => void;
  draggedId: string | null;
  dropTarget: SidebarDropTarget | null;
  onDragStart: (e: DragEvent, docId: string) => void;
  onDragOver: (e: DragEvent, target: SidebarDragTarget, el: HTMLElement) => void;
  onDragLeave: () => void;
  onDrop: (e: DragEvent) => void;
  onDragEnd: () => void;
  isMountExpanded: (key: string) => boolean;
  isMountLoading: (key: string) => boolean;
  getMountEntries: (key: string) => MountedShareTreeEntry[];
  onMountToggle: (mount: ShareMount) => void;
  onMountEntryToggle: (mount: ShareMount, entry: ShareTreeEntry) => void;
  onMountOpen: (mount: ShareMount) => void;
  onMountAddToTile: (mount: ShareMount) => void;
  onMountEntryOpen: (mount: ShareMount, entry: ShareTreeEntry) => void;
  onMountEntryAddToTile: (mount: ShareMount, entry: ShareTreeEntry) => void;
  onMountUnmount: (mount: ShareMount) => void;
}

const MAX_VISUAL_DEPTH = 10;

function mountTitle(mount: ResolvedShareMount): string {
  if (mount.resolved_title) return mount.resolved_title;
  return mount.target_kind === "folder" ? "Shared folder" : "Shared document";
}

function mountKey(mount: ShareMount): string {
  return mount.id;
}

function entryKey(mount: ShareMount, entry: ShareTreeEntry): string {
  return `${mount.id}:${entry.folder_token ?? entry.id}`;
}

export function DocumentTreeItem(props: DocumentTreeItemProps) {
  if (props.node.kind === "document" || props.node.kind === "folder") {
    return <DocumentRow {...props} node={props.node} />;
  }

  if (props.node.kind === "mount") {
    return <MountTreeItem {...props} node={props.node} />;
  }

  return <MountEntryTreeItem {...props} node={props.node} />;
}

function DocumentRow(
  props: DocumentTreeItemProps & {
    node: Extract<SidebarTreeNode, { kind: "document" | "folder" }>;
  },
) {
  const doc = () => props.node.document;
  const isFolder = () => props.node.kind === "folder";
  const isArchived = () => doc().archived_at != null;
  const isSelected = () => props.selectedId === doc().id;
  const isDragged = () => props.draggedId === doc().id;
  const isReady = () => props.isTitleReady(doc());
  const depth = () => Math.min(props.node.depth, MAX_VISUAL_DEPTH);
  const children = () => (props.node.kind === "folder" ? props.node.children : []);

  const dropIndicator = () => {
    const target = props.dropTarget;
    if (!target || target.itemId !== doc().id) return null;
    return target.position;
  };

  const handleClick = () => {
    if (!isFolder() && !isReady()) return;
    props.onSelect(doc().id);
  };

  const handleToggle = (e: MouseEvent) => {
    e.stopPropagation();
    props.onToggle(doc().id);
  };

  let rowRef: HTMLButtonElement | undefined;
  const dragTarget = (): SidebarDragTarget => ({
    id: doc().id,
    kind: isFolder() ? "folder" : "document",
    parentId: doc().parent_id ?? null,
    archivedAt: doc().archived_at ?? null,
  });

  return (
    <div>
      <div class="relative">
        <Show when={dropIndicator() === "before"}>
          <div
            class="absolute top-0 left-0 right-0 h-0.5 bg-primary z-10"
            style={{ "margin-left": `${depth() * 16 + 8}px` }}
          />
        </Show>
        <button
          ref={(el) => (rowRef = el)}
          class={`group w-full min-w-0 flex items-center gap-1.5 mx-1 px-3 py-1.5 text-xs text-left overflow-hidden transition-colors ${
            isSelected()
              ? "bg-sidebar-accent text-sidebar-foreground"
              : "text-sidebar-foreground/70 hover:bg-sidebar-accent"
          } ${isArchived() ? "opacity-50 italic" : ""} ${!isReady() ? "opacity-40 cursor-default" : ""} ${isDragged() ? "opacity-30" : ""} ${
            dropIndicator() === "inside" ? "bg-primary/20" : ""
          }`}
          style={{ "padding-left": `${depth() * 16 + 12}px` }}
          draggable={!isArchived() && isReady()}
          onClick={handleClick}
          onDragStart={(e) => props.onDragStart(e, doc().id)}
          onDragOver={(e) => props.onDragOver(e, dragTarget(), rowRef!)}
          onDragLeave={() => props.onDragLeave()}
          onDrop={(e) => props.onDrop(e)}
          onDragEnd={() => props.onDragEnd()}
          onContextMenu={(e) => {
            props.onContextMenu(e, doc());
          }}
        >
          <Show when={isFolder()}>
            <span
              class="shrink-0 size-4 flex items-center justify-center cursor-pointer"
              onClick={handleToggle}
            >
              <Show
                when={props.isExpanded(doc().id)}
                fallback={<ChevronRightIcon class="size-3" />}
              >
                <ChevronDownIcon class="size-3" />
              </Show>
            </span>
          </Show>
          <Show when={!isFolder()}>
            <span class="shrink-0 size-4" />
          </Show>
          <span class="shrink-0">
            <Show
              when={isFolder()}
              fallback={<FileTextIcon class="size-4 text-muted-foreground" />}
            >
              <FolderIcon class="size-4 text-muted-foreground" />
            </Show>
          </span>
          <span class="truncate">{props.getTitle(doc())}</span>
        </button>
        <Show when={dropIndicator() === "after"}>
          <div
            class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary z-10"
            style={{ "margin-left": `${depth() * 16 + 8}px` }}
          />
        </Show>
      </div>
      <Show when={isFolder() && props.isExpanded(doc().id)}>
        <For each={children()}>
          {(child) => (
            <DocumentTreeItem
              node={child}
              isExpanded={props.isExpanded}
              onToggle={props.onToggle}
              selectedId={props.selectedId}
              selectedMountKey={props.selectedMountKey}
              onSelect={props.onSelect}
              getTitle={props.getTitle}
              isTitleReady={props.isTitleReady}
              onContextMenu={props.onContextMenu}
              draggedId={props.draggedId}
              dropTarget={props.dropTarget}
              onDragStart={props.onDragStart}
              onDragOver={props.onDragOver}
              onDragLeave={props.onDragLeave}
              onDrop={props.onDrop}
              onDragEnd={props.onDragEnd}
              isMountExpanded={props.isMountExpanded}
              isMountLoading={props.isMountLoading}
              getMountEntries={props.getMountEntries}
              onMountToggle={props.onMountToggle}
              onMountEntryToggle={props.onMountEntryToggle}
              onMountOpen={props.onMountOpen}
              onMountAddToTile={props.onMountAddToTile}
              onMountEntryOpen={props.onMountEntryOpen}
              onMountEntryAddToTile={props.onMountEntryAddToTile}
              onMountUnmount={props.onMountUnmount}
            />
          )}
        </For>
      </Show>
    </div>
  );
}

function MountTreeItem(
  props: DocumentTreeItemProps & { node: Extract<SidebarTreeNode, { kind: "mount" }> },
) {
  const mount = () => props.node.mount;
  const isFolder = () => mount().target_kind === "folder";
  const isActive = () => mount().status === "active";
  const isSelected = () =>
    !isFolder() && props.selectedMountKey === `mount:${mount().id}:${mount().share_id}`;
  const isDragged = () => props.draggedId === mount().id;
  const depth = () => Math.min(props.node.depth, MAX_VISUAL_DEPTH);
  const key = () => mountKey(mount());
  const dropIndicator = () => {
    const target = props.dropTarget;
    if (!target || target.itemId !== mount().id) return null;
    return target.position === "inside" ? null : target.position;
  };

  const handleClick = () => {
    if (!isActive()) return;
    if (isFolder()) {
      props.onMountToggle(mount());
      return;
    }
    props.onMountOpen(mount());
  };

  const dragTarget = (): SidebarDragTarget => ({
    id: mount().id,
    kind: "mount",
    parentId: mount().parent_id ?? null,
    archivedAt: null,
  });

  let rowRef: HTMLButtonElement | undefined;

  return (
    <div>
      <ContextMenu modal={false}>
        <ContextMenuTrigger class="contents">
          <div class="relative">
            <Show when={dropIndicator() === "before"}>
              <div
                class="absolute top-0 left-0 right-0 h-0.5 bg-primary z-10"
                style={{ "margin-left": `${depth() * 16 + 8}px` }}
              />
            </Show>
            <button
              ref={(el) => (rowRef = el)}
              type="button"
              class={`group w-full min-w-0 flex items-center gap-1.5 mx-1 px-3 py-1.5 text-xs text-left overflow-hidden transition-colors ${
                isSelected()
                  ? "bg-sidebar-accent text-sidebar-foreground"
                  : isActive()
                    ? "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground"
                    : "opacity-50 text-sidebar-foreground/55"
              } ${isDragged() ? "opacity-30" : ""}`}
              style={{ "padding-left": `${depth() * 16 + 12}px` }}
              draggable={isActive()}
              onClick={handleClick}
              onDragStart={(e) => props.onDragStart(e, mount().id)}
              onDragOver={(event) => props.onDragOver(event, dragTarget(), rowRef!)}
              onDragLeave={() => props.onDragLeave()}
              onDrop={(event) => props.onDrop(event)}
              onDragEnd={() => props.onDragEnd()}
            >
              <Show when={isFolder()} fallback={<span class="shrink-0 size-4" />}>
                <span
                  class="shrink-0 size-4 flex items-center justify-center cursor-pointer"
                  onClick={(event) => {
                    event.stopPropagation();
                    if (isActive()) props.onMountToggle(mount());
                  }}
                >
                  <Show
                    when={props.isMountExpanded(key())}
                    fallback={<ChevronRightIcon class="size-3" />}
                  >
                    <ChevronDownIcon class="size-3" />
                  </Show>
                </span>
              </Show>
              <LinkIcon class="size-4 shrink-0 text-muted-foreground" />
              <span class="min-w-0 flex-1 truncate">{mountTitle(mount())}</span>
              <Show when={mount().password_protected}>
                <LockIcon class="size-3 shrink-0 text-muted-foreground" />
              </Show>
              <span class="shrink-0 text-[10px] text-muted-foreground">
                {mount().share.permission}
              </span>
              <Show when={props.isMountLoading(key())}>
                <Spinner class="size-3 shrink-0" />
              </Show>
            </button>
            <Show when={dropIndicator() === "after"}>
              <div
                class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary z-10"
                style={{ "margin-left": `${depth() * 16 + 8}px` }}
              />
            </Show>
          </div>
        </ContextMenuTrigger>
        <ContextMenuContent>
          <Show when={isActive() && !isFolder()}>
            <ContextMenuItem onSelect={() => props.onMountOpen(mount())}>
              <PanelRightIcon class="size-3.5" />
              Open
            </ContextMenuItem>
            <ContextMenuItem onSelect={() => props.onMountAddToTile(mount())}>
              <PanelRightIcon class="size-3.5" />
              Add to Tile
            </ContextMenuItem>
          </Show>
          <Show when={isActive() && isFolder()}>
            <ContextMenuItem onSelect={() => props.onMountToggle(mount())}>
              <PanelRightIcon class="size-3.5" />
              {props.isMountExpanded(key()) ? "Collapse" : "Expand"}
            </ContextMenuItem>
          </Show>
          <ContextMenuSeparator />
          <ContextMenuItem variant="destructive" onSelect={() => props.onMountUnmount(mount())}>
            <TrashIcon class="size-3.5" />
            Unmount
          </ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
      <Show when={isFolder() && props.isMountExpanded(key())}>
        <For
          each={buildMountChildRows(mount(), props.getMountEntries(key()), props.node.depth + 1)}
        >
          {(node) => <DocumentTreeItem {...props} node={node} />}
        </For>
      </Show>
    </div>
  );
}

function MountEntryTreeItem(
  props: DocumentTreeItemProps & {
    node: Extract<SidebarTreeNode, { kind: "mount-child-document" | "mount-child-folder" }>;
  },
) {
  const mount = () => props.node.mount;
  const entry = () => props.node.entry;
  const isFolder = () => props.node.kind === "mount-child-folder";
  const isSelected = () =>
    !isFolder() && props.selectedMountKey === `mount:${mount().id}:${entry().share_id}`;
  const depth = () => Math.min(props.node.depth, MAX_VISUAL_DEPTH);
  const key = () => entryKey(mount(), entry());

  const handleClick = () => {
    if (isFolder()) {
      props.onMountEntryToggle(mount(), entry());
      return;
    }
    props.onMountEntryOpen(mount(), entry());
  };

  return (
    <div>
      <ContextMenu modal={false}>
        <ContextMenuTrigger class="contents">
          <button
            type="button"
            class={`group w-full min-w-0 flex items-center gap-1.5 mx-1 px-3 py-1.5 text-xs text-left overflow-hidden transition-colors ${
              isSelected()
                ? "bg-sidebar-accent text-sidebar-foreground"
                : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground"
            }`}
            style={{ "padding-left": `${depth() * 16 + 12}px` }}
            onClick={handleClick}
          >
            <Show when={isFolder()} fallback={<span class="shrink-0 size-4" />}>
              <span
                class="shrink-0 size-4 flex items-center justify-center cursor-pointer"
                onClick={(event) => {
                  event.stopPropagation();
                  props.onMountEntryToggle(mount(), entry());
                }}
              >
                <Show
                  when={props.isMountExpanded(key())}
                  fallback={<ChevronRightIcon class="size-3" />}
                >
                  <ChevronDownIcon class="size-3" />
                </Show>
              </span>
            </Show>
            <Show
              when={isFolder()}
              fallback={<FileTextIcon class="size-4 shrink-0 text-muted-foreground" />}
            >
              <FolderIcon class="size-4 shrink-0 text-muted-foreground" />
            </Show>
            <span class="min-w-0 flex-1 truncate">{entry().label}</span>
            <Show when={props.isMountLoading(key())}>
              <Spinner class="size-3 shrink-0" />
            </Show>
          </button>
        </ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem
            onSelect={() => {
              if (isFolder()) props.onMountEntryToggle(mount(), entry());
              else props.onMountEntryOpen(mount(), entry());
            }}
          >
            <PanelRightIcon class="size-3.5" />
            {isFolder() ? (props.isMountExpanded(key()) ? "Collapse" : "Expand") : "Open"}
          </ContextMenuItem>
          <Show when={!isFolder()}>
            <ContextMenuItem onSelect={() => props.onMountEntryAddToTile(mount(), entry())}>
              <PanelRightIcon class="size-3.5" />
              Add to Tile
            </ContextMenuItem>
          </Show>
        </ContextMenuContent>
      </ContextMenu>
      <Show when={isFolder() && props.isMountExpanded(key())}>
        <For
          each={buildMountChildRows(mount(), props.getMountEntries(key()), props.node.depth + 1)}
        >
          {(node) => <DocumentTreeItem {...props} node={node} />}
        </For>
      </Show>
    </div>
  );
}
