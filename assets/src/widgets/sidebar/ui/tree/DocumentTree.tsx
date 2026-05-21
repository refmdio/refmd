import { Show, For } from "solid-js";
import { Spinner } from "@/shared/ui/spinner";
import { Button } from "@/shared/ui/button";
import { ScrollArea } from "@/shared/ui/scroll-area";
import type { DocumentResponse } from "@/entities/document";
import type { MountedShareTreeEntry, ShareMount, ShareTreeEntry } from "@/entities/mount";
import type { SidebarTreeNode } from "../../model/tree/rows";
import type { SidebarDragTarget, SidebarDropTarget } from "../../model/tree/use-tree-drag";
import { DocumentTreeItem } from "./DocumentTreeItem";

interface DocumentTreeProps {
  tree: SidebarTreeNode[];
  isLoading: boolean;
  isError: boolean;
  refetch: () => void;
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
  onRootDragOver: (e: DragEvent) => void;
  onRootDrop: (e: DragEvent) => void;
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

export function DocumentTree(props: DocumentTreeProps) {
  const isRootDropTarget = () =>
    props.dropTarget?.itemId === "__root__" && props.dropTarget?.position === "inside";

  return (
    <Show
      when={!props.isLoading}
      fallback={
        <div class="flex-1 flex items-center justify-center">
          <Spinner class="size-5" />
        </div>
      }
    >
      <Show
        when={!props.isError}
        fallback={
          <div class="flex-1 flex flex-col items-center justify-center gap-2 p-4">
            <p class="text-xs text-muted-foreground">Failed to load documents</p>
            <Button variant="outline" size="sm" onClick={props.refetch}>
              Retry
            </Button>
          </div>
        }
      >
        <Show
          when={props.tree.length > 0}
          fallback={
            <div
              class={`flex-1 flex items-center justify-center ${isRootDropTarget() ? "bg-primary/10" : ""}`}
              onDragOver={props.onRootDragOver}
              onDrop={props.onRootDrop}
              onDragLeave={props.onDragLeave}
            >
              <p class="text-xs text-muted-foreground">No documents yet</p>
            </div>
          }
        >
          <ScrollArea class="flex-1 [&_[data-slot=scroll-area-viewport]]:!overflow-x-hidden [&_[data-slot=scroll-area-viewport]_::-webkit-scrollbar]:!w-1.5">
            <div class="py-1">
              <For each={props.tree}>
                {(node) => (
                  <DocumentTreeItem
                    node={node}
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
              <div
                class={`h-8 ${isRootDropTarget() ? "bg-primary/10" : ""}`}
                onDragOver={props.onRootDragOver}
                onDrop={props.onRootDrop}
                onDragLeave={props.onDragLeave}
              />
            </div>
          </ScrollArea>
        </Show>
      </Show>
    </Show>
  );
}
