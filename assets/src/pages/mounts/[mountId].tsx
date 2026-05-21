import { MountedShareWorkspace } from "@/widgets/share-workspace";
import { DashboardWorkspace } from "@/widgets/document-workspace";

export default function MountRoute() {
  return <MountedShareWorkspace fallback={<DashboardWorkspace />} />;
}
