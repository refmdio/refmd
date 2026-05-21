import { createSignal, Show, For } from "solid-js";
import { ArchiveIcon, ChevronRightIcon, ChevronDownIcon } from "lucide-solid";
import { DocumentTreeItem } from "../tree/DocumentTreeItem";
import { DocumentContextMenu } from "../menu/DocumentContextMenu";
import { useDocuments, useDocumentTitles, useExpandedFolders } from "@/entities/document";
import type { DocumentResponse } from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { Notice } from "@/shared/lib/notice";
import { useSidebarDocumentTreeHandlers } from "../../model/tree/use-document-tree-handlers";
import { useDocumentSharePermissions } from "@/features/workspace";
import { buildSidebarRows } from "../../model/tree/rows";

export function ArchiveSection() {
  const workspaceId = () => currentWorkspaceId();
  const { flatDocuments } = useDocuments(workspaceId);
  const sharePermissions = useDocumentSharePermissions(workspaceId);
  const { getTitle, isTitleReady } = useDocumentTitles(flatDocuments, workspaceId);
  const { isExpanded, toggle, expand } = useExpandedFolders(workspaceId);

  const archiveTree = () => {
    const archived = flatDocuments().filter((d) => !!d.archived_at);
    if (archived.length === 0) return [];
    const archivedIds = new Set(archived.map((d) => d.id));
    const rerooted = archived.map((d) =>
      d.parent_id && !archivedIds.has(d.parent_id) ? { ...d, parent_id: null } : d,
    );
    return buildSidebarRows(rerooted as DocumentResponse[], []);
  };

  const [archiveExpanded, setArchiveExpanded] = createSignal(false);

  const {
    drag,
    selectedId,
    contextTarget,
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
        canManageShares={false}
        canDeleteShares={sharePermissions.canDeleteShares()}
        canPublishPublic={false}
        setError={(message) => {
          if (message) new Notice(message);
        }}
      >
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
                    selectedMountKey={null}
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
                    isMountExpanded={() => false}
                    isMountLoading={() => false}
                    getMountEntries={() => []}
                    onMountToggle={() => undefined}
                    onMountEntryToggle={() => undefined}
                    onMountOpen={() => undefined}
                    onMountAddToTile={() => undefined}
                    onMountEntryOpen={() => undefined}
                    onMountEntryAddToTile={() => undefined}
                    onMountUnmount={() => undefined}
                  />
                )}
              </For>
            </div>
          </Show>
        </div>
      </DocumentContextMenu>
    </Show>
  );
}
