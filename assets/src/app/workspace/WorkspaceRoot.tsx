import { createEffect, getOwner, onCleanup, type ParentProps } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import { useDocuments, useDocumentTitles } from "@/entities/document";
import { useSettings } from "@/entities/settings";
import { currentWorkspaceId, setCurrentWorkspaceId, useWorkspaces } from "@/entities/workspace";
import { useWorkspaceKekRotationMonitor } from "@/app/workspace/use-workspace-kek-rotation-monitor";
import { AppLayout } from "@/app/layout/AppLayout";
import { useCorePluginLifecycle } from "@/app/bootstrap/use-core-plugin-lifecycle";
import { useDocumentWorkspaceRuntime } from "@/app/bootstrap/use-document-workspace-runtime";
import { useOfflineSync } from "@/app/bootstrap/use-offline-sync";
import { usePendingDevices } from "@/features/devices";
import { installPublicationRenameAutoSync } from "@/features/editor";
import { createWorkspaceWithInitialKek } from "@/features/workspace";
import { disposePanelWorkspace, usePanelWorkspace } from "@/features/panel";
import { getDocumentRuntime } from "@/shared/lib/document/manager";
import { setDefaultPluginRenderOwner } from "@/shared/lib/plugin/render";

export function WorkspaceRoot(props: ParentProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { workspaces, workspacesNeedingRotation } = useWorkspaces();
  const { pendingCount } = usePendingDevices();
  const documentWorkspace = usePanelWorkspace();
  const workspaceId = () => currentWorkspaceId();
  const { flatDocuments } = useDocuments(workspaceId);
  const { getTitle: getTitleFromDoc } = useDocumentTitles(flatDocuments, workspaceId);
  const disposePluginRenderOwner = setDefaultPluginRenderOwner(getOwner());
  const disposePublicationRenameSync = installPublicationRenameAutoSync();

  onCleanup(() => disposePanelWorkspace());
  onCleanup(disposePluginRenderOwner);
  onCleanup(disposePublicationRenameSync);

  useSettings();

  const app = useDocumentWorkspaceRuntime(documentWorkspace, navigate, queryClient);
  useCorePluginLifecycle(app, documentWorkspace);
  useOfflineSync();
  useWorkspaceKekRotationMonitor(workspacesNeedingRotation, queryClient);

  getDocumentRuntime().setTitleResolver((doc) => {
    const found = flatDocuments().find((candidate) => candidate.id === doc.id);
    return found ? getTitleFromDoc(found) : "Untitled";
  });

  let previousWorkspaceId: string | null = null;
  createEffect(() => {
    const workspaceId = currentWorkspaceId();
    if (previousWorkspaceId !== null && workspaceId !== previousWorkspaceId) {
      documentWorkspace.resetWorkspace();
    }
    previousWorkspaceId = workspaceId;
  });

  const handleSelectWorkspace = (workspaceId: string) => {
    setCurrentWorkspaceId(workspaceId);
    navigate("/dashboard");
  };

  const handleCreateWorkspace = async (data: {
    name: string;
    description?: string;
    icon?: string;
  }): Promise<void> => {
    const workspaceId = await createWorkspaceWithInitialKek(data);
    if (!workspaceId) return;

    await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    setCurrentWorkspaceId(workspaceId);
    navigate("/dashboard");
  };

  return (
    <AppLayout
      workspaces={workspaces()}
      currentWorkspaceId={currentWorkspaceId()}
      pendingDeviceCount={pendingCount()}
      onSelectWorkspace={handleSelectWorkspace}
      onCreateWorkspace={handleCreateWorkspace}
    >
      {props.children}
    </AppLayout>
  );
}
