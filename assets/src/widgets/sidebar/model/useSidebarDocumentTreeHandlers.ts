import { useDocumentTreeHandlers } from "@/features/document";
import { closeDocumentPanels, usePanelWorkspace } from "@/features/panel";

type SidebarDocumentTreeHandlersOptions = Omit<
  Parameters<typeof useDocumentTreeHandlers>[0],
  "onAddToTile" | "onDeleteSuccess"
>;

export function useSidebarDocumentTreeHandlers(options: SidebarDocumentTreeHandlersOptions) {
  const workspace = usePanelWorkspace();

  const handlers = useDocumentTreeHandlers({
    ...options,
    onAddToTile: (doc) => workspace.addToTile({ id: doc.id, title: options.getTitle(doc) }),
    onDeleteSuccess: (documentId) => closeDocumentPanels(workspace, documentId),
  });

  return {
    ...handlers,
    folders: () => options.flatDocuments().filter((doc) => doc.doc_type === "folder"),
  };
}
