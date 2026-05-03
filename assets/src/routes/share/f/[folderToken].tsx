import { ShareFolderWorkspace } from "@/widgets/share-workspace";
import { DocumentWorkspace } from "@/widgets/document-workspace";

export default function ShareFolderRoute() {
  return (
    <ShareFolderWorkspace>
      <DocumentWorkspace useCurrentWorkspaceId={false} />
    </ShareFolderWorkspace>
  );
}
