import { Show, For } from "solid-js";
import { ChevronRightIcon, ChevronDownIcon, FolderIcon, FileTextIcon } from "lucide-solid";
import type { DocumentTreeNode, DocumentResponse, DropTarget } from "@/entities/document";

interface DocumentTreeItemProps {
  node: DocumentTreeNode;
  isExpanded: (id: string) => boolean;
  onToggle: (id: string) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  getTitle: (doc: DocumentResponse) => string;
  onContextMenu: (e: MouseEvent, doc: DocumentResponse) => void;
  draggedId: string | null;
  dropTarget: DropTarget | null;
  onDragStart: (e: DragEvent, docId: string) => void;
  onDragOver: (e: DragEvent, doc: DocumentResponse, el: HTMLElement) => void;
  onDragLeave: () => void;
  onDrop: (e: DragEvent) => void;
  onDragEnd: () => void;
}

const MAX_VISUAL_DEPTH = 10;

export function DocumentTreeItem(props: DocumentTreeItemProps) {
  const doc = () => props.node.document;
  const isFolder = () => doc().doc_type === "folder";
  const isArchived = () => doc().archived_at != null;
  const isSelected = () => props.selectedId === doc().id;
  const isDragged = () => props.draggedId === doc().id;
  const depth = () => Math.min(props.node.depth, MAX_VISUAL_DEPTH);

  const dropIndicator = () => {
    const target = props.dropTarget;
    if (!target || target.documentId !== doc().id) return null;
    return target.position;
  };

  const handleClick = () => {
    props.onSelect(doc().id);
  };

  const handleToggle = (e: MouseEvent) => {
    e.stopPropagation();
    props.onToggle(doc().id);
  };

  let rowRef: HTMLButtonElement | undefined;

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
          class={`group w-full flex items-center gap-1.5 mx-1 px-3 py-1.5 text-xs text-left rounded-md transition-colors ${
            isSelected()
              ? "bg-sidebar-accent text-sidebar-foreground"
              : "text-sidebar-foreground/70 hover:bg-sidebar-accent"
          } ${isArchived() ? "opacity-50 italic" : ""} ${isDragged() ? "opacity-30" : ""} ${
            dropIndicator() === "inside" ? "bg-primary/20" : ""
          }`}
          style={{ "padding-left": `${depth() * 16 + 12}px` }}
          draggable={!isArchived()}
          onClick={handleClick}
          onDragStart={(e) => props.onDragStart(e, doc().id)}
          onDragOver={(e) => props.onDragOver(e, doc(), rowRef!)}
          onDragLeave={() => props.onDragLeave()}
          onDrop={(e) => props.onDrop(e)}
          onDragEnd={() => props.onDragEnd()}
          onContextMenu={(e) => {
            e.preventDefault();
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
        <For each={props.node.children}>
          {(child) => (
            <DocumentTreeItem
              node={child}
              isExpanded={props.isExpanded}
              onToggle={props.onToggle}
              selectedId={props.selectedId}
              onSelect={props.onSelect}
              getTitle={props.getTitle}
              onContextMenu={props.onContextMenu}
              draggedId={props.draggedId}
              dropTarget={props.dropTarget}
              onDragStart={props.onDragStart}
              onDragOver={props.onDragOver}
              onDragLeave={props.onDragLeave}
              onDrop={props.onDrop}
              onDragEnd={props.onDragEnd}
            />
          )}
        </For>
      </Show>
    </div>
  );
}
