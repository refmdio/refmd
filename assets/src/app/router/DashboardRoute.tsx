import DashboardPage from "@/routes/dashboard";
import { usePanelWorkspace } from "@/features/panel";
import { useDocumentRouteController } from "@/app/router/document-route-controller";

export function DashboardRoute() {
  const documentWorkspace = usePanelWorkspace();
  useDocumentRouteController(documentWorkspace);

  return <DashboardPage />;
}
