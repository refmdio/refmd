import { createEffect, onCleanup, type ParentProps } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import { useSettings } from "@/entities/settings";
import { currentWorkspaceId, setCurrentWorkspaceId, useWorkspaces } from "@/entities/workspace";
import { useWorkspaceKekRotationMonitor } from "@/app/workspace/useWorkspaceKekRotationMonitor";
import { AppLayout } from "@/app/layout/AppLayout";
import { useCorePluginLifecycle } from "@/app/bootstrap/useCorePluginLifecycle";
import { useDocumentWorkspaceRuntime } from "@/app/bootstrap/useDocumentWorkspaceRuntime";
import { useOfflineSync } from "@/app/bootstrap/useOfflineSync";
import { usePendingDevices } from "@/features/devices";
import { createWorkspaceWithInitialKek } from "@/features/workspace";
import { disposePanelWorkspace, usePanelWorkspace } from "@/features/panel";

export function WorkspaceRoot(props: ParentProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { workspaces, workspacesNeedingRotation } = useWorkspaces();
  const { pendingCount } = usePendingDevices();
  const documentWorkspace = usePanelWorkspace();

  onCleanup(() => disposePanelWorkspace());

  useSettings();

  const app = useDocumentWorkspaceRuntime(documentWorkspace, navigate, queryClient);
  useCorePluginLifecycle(app, documentWorkspace);
  useOfflineSync();
  useWorkspaceKekRotationMonitor(workspacesNeedingRotation, queryClient);

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
