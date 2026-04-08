import { createSignal, Show } from "solid-js";
import { offlineMode } from "@/shared/lib/offline/offline-state";
import { Notice } from "@/shared/lib/notice";
import { FilePlusIcon, FolderPlusIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { DocumentTree } from "./DocumentTree";
import { DocumentContextMenu } from "./DocumentContextMenu";
import { ArchiveSection } from "./ArchiveSection";
import {
  buildDocumentTree,
  useDocuments,
  useDocumentTitles,
  useExpandedFolders,
  selectedDocumentId,
} from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { CreateDocumentDialog, CreateFolderDialog } from "@/features/document";
import { useSidebarDocumentTreeHandlers } from "../model/useSidebarDocumentTreeHandlers";

export function DocumentTreePanel() {
  const workspaceId = () => currentWorkspaceId();
  const { flatDocuments, query } = useDocuments(workspaceId);
  const { getTitle, isTitleReady } = useDocumentTitles(flatDocuments, workspaceId);
  const { isExpanded, toggle, expand } = useExpandedFolders(workspaceId);

  const activeTree = () => buildDocumentTree(flatDocuments().filter((d) => !d.archived_at));

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
    contextPosition,
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
          <div class="flex-1 overflow-y-auto">
            <DocumentTree
              tree={activeTree()}
              isLoading={query.isLoading}
              isError={query.isError}
              refetch={() => query.refetch()}
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
              onRootDragOver={drag.handleRootDragOver}
              onRootDrop={drag.handleRootDrop}
            />
          </div>
        </Show>
      </div>

      <div class="mt-auto shrink-0">
        <ArchiveSection />
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
    </>
  );
}
