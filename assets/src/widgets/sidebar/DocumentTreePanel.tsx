import { createSignal, Show } from "solid-js";
import { offlineMode } from "@/shared/lib/offline/offline-state";
import { useQueryClient } from "@tanstack/solid-query";
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
  useDocumentDrag,
  selectedDocumentId,
  setSelectedDocumentId,
} from "@/entities/document";
import type { DocumentResponse } from "@/entities/document";
import { usePanelWorkspace, hasDocumentPanels, findFirstPanelId } from "@/features/panel";
import { currentWorkspaceId } from "@/entities/workspace";
import { documentManager } from "@/shared/lib/document-manager";
import {
  createFolder,
  renameDocument,
  moveDocument,
  archiveDocument,
  unarchiveDocument,
  deleteDocument,
  CreateDocumentDialog,
  CreateFolderDialog,
} from "@/features/document";

export function DocumentTreePanel() {
  const queryClient = useQueryClient();
  const workspaceId = () => currentWorkspaceId();
  const { flatDocuments, query } = useDocuments(workspaceId);
  const { getTitle, isTitleReady } = useDocumentTitles(flatDocuments, workspaceId);
  const { isExpanded, toggle, expand } = useExpandedFolders(workspaceId);
  const workspace = usePanelWorkspace();

  const activeTree = () => buildDocumentTree(flatDocuments().filter((d) => !d.archived_at));

  const handleDragDrop = async (draggedId: string, parentId: string | null, position: number) => {
    const wsId = workspaceId();
    if (!wsId) return;
    try {
      await moveDocument(draggedId, wsId, parentId, position);
      invalidateDocuments();
      if (parentId) expand(parentId);
    } catch (e) {
      console.error("Failed to reorder document:", e);
    }
  };

  const drag = useDocumentDrag(flatDocuments, handleDragDrop, expand);

  const [createDocOpen, setCreateDocOpen] = createSignal(false);
  const [createFolderOpen, setCreateFolderOpen] = createSignal(false);
  const [contextTarget, setContextTarget] = createSignal<DocumentResponse | null>(null);
  const [contextPos, setContextPos] = createSignal<{ x: number; y: number } | null>(null);

  const invalidateDocuments = () => {
    queryClient.invalidateQueries({ queryKey: ["documents", workspaceId()] });
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

  const handleCreateDocument = async (title: string) => {
    const docId = await documentManager.createDocument(title, selectedParentId());
    documentManager.notifyDocumentCreate(docId);
    invalidateDocuments();
    setSelectedDocumentId(docId);
  };

  const handleCreateFolder = async (name: string) => {
    const wsId = workspaceId();
    if (!wsId || offlineMode()) return;
    const folderId = await createFolder(wsId, name, selectedParentId());
    invalidateDocuments();
    setSelectedDocumentId(folderId);
    expand(folderId);
  };

  const handleRename = async (doc: DocumentResponse, newTitle: string) => {
    const wsId = workspaceId();
    if (!wsId) return;
    const oldTitle = getTitle(doc);
    await renameDocument(doc, newTitle, wsId);
    documentManager.notifyDocumentRename(doc.id, oldTitle);
    invalidateDocuments();
  };

  const handleMove = async (doc: DocumentResponse, parentId: string | null) => {
    const wsId = workspaceId();
    if (!wsId) return;
    const siblings = flatDocuments().filter(
      (d) => (d.parent_id ?? null) === parentId && d.id !== doc.id,
    );
    const position = siblings.length;
    await moveDocument(doc.id, wsId, parentId, position);
    invalidateDocuments();
    if (parentId) expand(parentId);
  };

  const handleArchive = async (doc: DocumentResponse) => {
    await archiveDocument(doc.id);
    invalidateDocuments();
  };

  const handleUnarchive = async (doc: DocumentResponse) => {
    await unarchiveDocument(doc.id);
    invalidateDocuments();
  };

  const handleDelete = async (doc: DocumentResponse) => {
    await deleteDocument(doc.id);
    documentManager.notifyDocumentDelete(doc.id);
    if (selectedDocumentId() === doc.id) {
      setSelectedDocumentId(null);
    }
    const state = workspace.mosaicState();
    if (state && hasDocumentPanels(state, doc.id)) {
      let panelId = findFirstPanelId(state, doc.id);
      while (panelId) {
        workspace.closePanel(panelId);
        const next = workspace.mosaicState();
        panelId = next ? findFirstPanelId(next, doc.id) : null;
      }
    }
    invalidateDocuments();
  };

  const handleContextMenu = (e: MouseEvent, doc: DocumentResponse) => {
    setContextTarget(doc);
    setContextPos({ x: e.clientX, y: e.clientY });
  };

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
              selectedId={selectedDocumentId()}
              onSelect={(id) => {
                setSelectedDocumentId(id);
                const doc = flatDocuments().find((d) => d.id === id);
                if (doc && doc.doc_type === "document" && isTitleReady(doc)) {
                  documentManager.openDocument(doc.id, getTitle(doc));
                }
              }}
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
        position={contextPos()}
        onClose={() => {
          setContextTarget(null);
          setContextPos(null);
        }}
        getTitle={getTitle}
        isTitleReady={isTitleReady}
        folders={flatDocuments().filter((d) => d.doc_type === "folder")}
        onRename={handleRename}
        onMove={handleMove}
        onAddToTile={(doc) => workspace.addToTile({ id: doc.id, title: getTitle(doc) })}
        onArchive={handleArchive}
        onUnarchive={handleUnarchive}
        onDelete={handleDelete}
      />

      <CreateDocumentDialog
        open={createDocOpen()}
        onOpenChange={setCreateDocOpen}
        onSubmit={handleCreateDocument}
      />

      <CreateFolderDialog
        open={createFolderOpen()}
        onOpenChange={setCreateFolderOpen}
        onSubmit={handleCreateFolder}
      />
    </>
  );
}
