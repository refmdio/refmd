import { ShareDocumentWorkspace } from "@/widgets/share-workspace";
import { DocumentWorkspace } from "@/widgets/document-workspace";

export default function ShareDocumentRoute() {
  return (
    <ShareDocumentWorkspace>
      <DocumentWorkspace useCurrentWorkspaceId={false} />
    </ShareDocumentWorkspace>
  );
}
