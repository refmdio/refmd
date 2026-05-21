import { useQueryClient } from "@tanstack/solid-query";
import { createSignal, type Accessor } from "solid-js";
import {
  useDocumentDrag,
  selectedDocumentId,
  setSelectedDocumentId,
  type DocumentResponse,
} from "@/entities/document";
import { getApp } from "@/shared/lib/workspace/app";
import { Notice } from "@/shared/lib/notice";
import { createFolder } from "../../lib/folder/create";
import { archiveDocument, deleteDocument, unarchiveDocument } from "../../lib/document/actions";
import { moveDocument } from "../../lib/document/move";
import { renameDocument } from "../../lib/document/rename";

interface UseDocumentTreeHandlersOptions {
  workspaceId: Accessor<string | null | undefined>;
  flatDocuments: Accessor<DocumentResponse[]>;
  getTitle: (doc: DocumentResponse) => string;
  isTitleReady: (doc: DocumentResponse) => boolean;
  expand: (folderId: string) => void;
  selectedParentId?: Accessor<string | null>;
  isOffline?: Accessor<boolean>;
  onAddToTile?: (doc: DocumentResponse) => void;
  onDeleteSuccess?: (documentId: string) => void;
  onDragDropError?: (error: unknown) => void;
}

export function useDocumentTreeHandlers(options: UseDocumentTreeHandlersOptions) {
  const { documents } = getApp();
  const queryClient = useQueryClient();
  const [contextTarget, setContextTarget] = createSignal<DocumentResponse | null>(null);

  const invalidateDocuments = () => {
    queryClient.invalidateQueries({ queryKey: ["documents", options.workspaceId()] });
  };

  const moveAndInvalidate = async (
    documentId: string,
    parentId: string | null,
    position: number,
  ) => {
    const wsId = options.workspaceId();
    if (!wsId) return;
    await moveDocument(documentId, wsId, parentId, position);
    invalidateDocuments();
    if (parentId) options.expand(parentId);
  };

  const handleDragDrop = async (draggedId: string, parentId: string | null, position: number) => {
    try {
      await moveAndInvalidate(draggedId, parentId, position);
    } catch (error) {
      if (options.onDragDropError) {
        options.onDragDropError(error);
        return;
      }
      throw error;
    }
  };

  const addDocumentToTile = (doc: DocumentResponse) => {
    if (!options.onAddToTile) return;
    if (doc.doc_type !== "document" || !options.isTitleReady(doc)) return;
    options.onAddToTile(doc);
  };

  const drag = useDocumentDrag(
    options.flatDocuments,
    handleDragDrop,
    options.expand,
    options.onAddToTile
      ? (documentId) => {
          const doc = options.flatDocuments().find((candidate) => candidate.id === documentId);
          if (doc) addDocumentToTile(doc);
        }
      : undefined,
  );

  const handleCreateDocument = options.selectedParentId
    ? async (title: string) => {
        const documentId = await documents.createDocument(title, options.selectedParentId!());
        invalidateDocuments();
        setSelectedDocumentId(documentId);
      }
    : undefined;

  const handleCreateFolder = options.selectedParentId
    ? async (name: string) => {
        const wsId = options.workspaceId();
        if (!wsId || options.isOffline?.()) return;
        const folderId = await createFolder(wsId, name, options.selectedParentId!());
        invalidateDocuments();
        setSelectedDocumentId(folderId);
        options.expand(folderId);
      }
    : undefined;

  const handleRename = async (doc: DocumentResponse, newTitle: string) => {
    const wsId = options.workspaceId();
    if (!wsId) return;
    const oldTitle = options.getTitle(doc);
    await renameDocument(doc, newTitle, wsId, oldTitle);
    invalidateDocuments();
  };

  const handleMove = async (doc: DocumentResponse, parentId: string | null) => {
    const siblings = options
      .flatDocuments()
      .filter((candidate) => (candidate.parent_id ?? null) === parentId && candidate.id !== doc.id);
    await moveAndInvalidate(doc.id, parentId, siblings.length);
  };

  const handleArchive = async (doc: DocumentResponse) => {
    try {
      await archiveDocument(doc.id);
      invalidateDocuments();
    } catch {
      new Notice("Failed to archive document");
    }
  };

  const handleUnarchive = async (doc: DocumentResponse) => {
    try {
      await unarchiveDocument(doc.id);
      invalidateDocuments();
    } catch {
      new Notice("Failed to unarchive document");
    }
  };

  const handleDelete = async (doc: DocumentResponse) => {
    await deleteDocument(doc.id);
    if (selectedDocumentId() === doc.id) {
      setSelectedDocumentId(null);
    }
    options.onDeleteSuccess?.(doc.id);
    invalidateDocuments();
  };

  const handleSelect = (documentId: string) => {
    setSelectedDocumentId(documentId);
    const doc = options.flatDocuments().find((candidate) => candidate.id === documentId);
    if (doc && doc.doc_type === "document" && options.isTitleReady(doc)) {
      documents.openDocument(doc.id);
    }
  };

  const handleContextMenu = (_e: MouseEvent, doc: DocumentResponse) => {
    setContextTarget(doc);
  };

  const closeContextMenu = () => {
    setContextTarget(null);
  };

  return {
    invalidateDocuments,
    drag,
    selectedId: selectedDocumentId,
    contextTarget,
    handleSelect,
    handleContextMenu,
    closeContextMenu,
    handleAddToTile: addDocumentToTile,
    handleCreateDocument,
    handleCreateFolder,
    handleRename,
    handleMove,
    handleArchive,
    handleUnarchive,
    handleDelete,
  };
}
