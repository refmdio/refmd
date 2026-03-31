import { createSignal, Show, For } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import { ArchiveIcon, ChevronRightIcon, ChevronDownIcon } from "lucide-solid";
import { DocumentTreeItem } from "./DocumentTreeItem";
import { DocumentContextMenu } from "./DocumentContextMenu";
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
import { usePanelWorkspace, closeDocumentPanels } from "@/features/panel";
import { currentWorkspaceId } from "@/entities/workspace";
import { documentNavigation } from "@/shared/lib/document-navigation";
import {
  moveDocument,
  renameDocument,
  unarchiveDocument,
  deleteDocument,
} from "@/features/document";

export function ArchiveSection() {
  const queryClient = useQueryClient();
  const workspaceId = () => currentWorkspaceId();
  const { flatDocuments } = useDocuments(workspaceId);
  const { getTitle, isTitleReady } = useDocumentTitles(flatDocuments, workspaceId);
  const { isExpanded, toggle, expand } = useExpandedFolders(workspaceId);
  const workspace = usePanelWorkspace();

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
  const [contextTarget, setContextTarget] = createSignal<DocumentResponse | null>(null);
  const [contextPos, setContextPos] = createSignal<{ x: number; y: number } | null>(null);

  const invalidateDocuments = () => {
    queryClient.invalidateQueries({ queryKey: ["documents", workspaceId()] });
  };

  const handleDragDrop = async (draggedId: string, parentId: string | null, position: number) => {
    const wsId = workspaceId();
    if (!wsId) return;
    await moveDocument(draggedId, wsId, parentId, position);
    invalidateDocuments();
    if (parentId) expand(parentId);
  };

  const drag = useDocumentDrag(flatDocuments, handleDragDrop, expand);

  const handleContextMenu = (e: MouseEvent, doc: DocumentResponse) => {
    setContextTarget(doc);
    setContextPos({ x: e.clientX, y: e.clientY });
  };

  const handleRename = async (doc: DocumentResponse, newTitle: string) => {
    const wsId = workspaceId();
    if (!wsId) return;
    const oldTitle = getTitle(doc);
    await renameDocument(doc, newTitle, wsId, oldTitle);
    invalidateDocuments();
  };

  const handleMove = async (doc: DocumentResponse, parentId: string | null) => {
    const wsId = workspaceId();
    if (!wsId) return;
    const siblings = flatDocuments().filter(
      (d) => (d.parent_id ?? null) === parentId && d.id !== doc.id,
    );
    await moveDocument(doc.id, wsId, parentId, siblings.length);
    invalidateDocuments();
    if (parentId) expand(parentId);
  };

  const handleUnarchive = async (doc: DocumentResponse) => {
    await unarchiveDocument(doc.id);
    invalidateDocuments();
  };

  const handleDelete = async (doc: DocumentResponse) => {
    await deleteDocument(doc.id);
    if (selectedDocumentId() === doc.id) {
      setSelectedDocumentId(null);
    }
    closeDocumentPanels(workspace, doc.id);
    invalidateDocuments();
  };

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
                  selectedId={selectedDocumentId()}
                  onSelect={(id) => {
                    setSelectedDocumentId(id);
                    const doc = flatDocuments().find((d) => d.id === id);
                    if (doc && doc.doc_type === "document" && isTitleReady(doc)) {
                      documentNavigation.openDocument(doc.id);
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
                />
              )}
            </For>
          </div>
        </Show>
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
        onArchive={async () => {}}
        onUnarchive={handleUnarchive}
        onDelete={handleDelete}
      />
    </Show>
  );
}
