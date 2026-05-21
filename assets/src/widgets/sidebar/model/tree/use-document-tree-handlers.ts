import type { Accessor } from "solid-js";
import { useDocumentTreeHandlers } from "@/features/document";
import { closeDocumentPanels, usePanelWorkspace } from "@/features/panel";
import type { ShareMount } from "@/entities/mount";
import { useSidebarTreeDrag } from "./use-tree-drag";

type SidebarDocumentTreeHandlersOptions = Omit<
  Parameters<typeof useDocumentTreeHandlers>[0],
  "onAddToTile" | "onDeleteSuccess"
> & {
  shareMounts?: Accessor<ShareMount[]>;
};

export function useSidebarDocumentTreeHandlers(options: SidebarDocumentTreeHandlersOptions) {
  const workspace = usePanelWorkspace();

  const handlers = useDocumentTreeHandlers({
    ...options,
    onAddToTile: (doc) => workspace.addToTile({ id: doc.id, title: options.getTitle(doc) }),
    onDeleteSuccess: (documentId) => closeDocumentPanels(workspace, documentId),
  });
  const drag = useSidebarTreeDrag({
    workspaceId: options.workspaceId,
    flatDocuments: options.flatDocuments,
    shareMounts: options.shareMounts ?? (() => []),
    expand: options.expand,
    onExternalDocumentDrop: (documentId) => {
      const doc = options.flatDocuments().find((candidate) => candidate.id === documentId);
      if (doc && options.isTitleReady(doc)) {
        workspace.addToTile({ id: doc.id, title: options.getTitle(doc) });
      }
    },
    onDragDropError: options.onDragDropError,
  });

  return {
    ...handlers,
    drag,
    folders: () => options.flatDocuments().filter((doc) => doc.doc_type === "folder"),
  };
}
