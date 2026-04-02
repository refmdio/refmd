import { createSignal, Show, For } from "solid-js";
import { ArchiveIcon, ChevronRightIcon, ChevronDownIcon } from "lucide-solid";
import { DocumentTreeItem } from "./DocumentTreeItem";
import { DocumentContextMenu } from "./DocumentContextMenu";
import {
  buildDocumentTree,
  useDocuments,
  useDocumentTitles,
  useExpandedFolders,
} from "@/entities/document";
import type { DocumentResponse } from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { useSidebarDocumentTreeHandlers } from "./useSidebarDocumentTreeHandlers";

export function ArchiveSection() {
  const workspaceId = () => currentWorkspaceId();
  const { flatDocuments } = useDocuments(workspaceId);
  const { getTitle, isTitleReady } = useDocumentTitles(flatDocuments, workspaceId);
  const { isExpanded, toggle, expand } = useExpandedFolders(workspaceId);

  const archiveTree = () => {
    const archived = flatDocuments().filter((d) => !!d.archived_at);
    if (archived.length === 0) return [];
    const archivedIds = new Set(archived.map((d) => d.id));
    const rerooted = archived.map((d) =>
      d.parent_id && !archivedIds.has(d.parent_id) ? { ...d, parent_id: null } : d,
    );
    return buildDocumentTree(rerooted as DocumentResponse[]);
  };

  const [archiveExpanded, setArchiveExpanded] = createSignal(false);

  const {
    drag,
    selectedId,
    contextTarget,
    contextPosition,
    handleSelect,
    handleContextMenu,
    closeContextMenu,
    handleAddToTile,
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
  });

  return (
    <Show when={archiveTree().length > 0}>
      <div class="shrink-0">
        <button
          class="w-full flex items-center gap-1.5 px-4 py-1.5 text-xs text-muted-foreground/70 hover:bg-sidebar-accent"
          onClick={() => setArchiveExpanded((v) => !v)}
        >
          <span class="shrink-0 size-4 flex items-center justify-center">
            <Show when={archiveExpanded()} fallback={<ChevronRightIcon class="size-3" />}>
              <ChevronDownIcon class="size-3" />
            </Show>
          </span>
          <ArchiveIcon class="size-4" />
          <span>Archive</span>
        </button>
        <Show when={archiveExpanded()}>
          <div class="py-1 max-h-48 overflow-y-auto overflow-x-hidden">
            <For each={archiveTree()}>
              {(node) => (
                <DocumentTreeItem
                  node={node}
                  isExpanded={isExpanded}
                  onToggle={toggle}
                  selectedId={selectedId()}
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
                />
              )}
            </For>
          </div>
        </Show>
      </div>

      <DocumentContextMenu
        targetDoc={contextTarget()}
        position={contextPosition()}
        onClose={closeContextMenu}
        getTitle={getTitle}
        isTitleReady={isTitleReady}
        folders={folders()}
        onRename={handleRename}
        onMove={handleMove}
        onAddToTile={handleAddToTile}
        onArchive={handleArchive}
        onUnarchive={handleUnarchive}
        onDelete={handleDelete}
      />
    </Show>
  );
}
