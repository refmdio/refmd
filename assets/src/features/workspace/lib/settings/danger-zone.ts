import { createSignal, type Accessor } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import type { WorkspaceRotationInfo } from "@/shared/api/devices";
import type { components } from "@/shared/api";
import { discardWorkspaceSelection, setCurrentWorkspaceId } from "@/entities/workspace";
import { removeWorkspaceMemberWithKeyDirectory } from "../members/remove-member";
type TriggerKekRotationFn = (rotationList: WorkspaceRotationInfo[]) => Promise<void>;
import { deleteWorkspace } from "./crud";
type WorkspacesListResponse = components["schemas"]["WorkspacesListResponse"];

interface UseWorkspaceDangerZoneOptions {
  workspaceId: Accessor<string | null | undefined>;
  currentUserId: Accessor<string | undefined>;
  setError: (value: string | null) => void;
  triggerKekRotation: TriggerKekRotationFn;
  closePluginRuntimeByWorkspace?: (workspaceId: string, reason?: string) => void | Promise<void>;
  releasePluginRuntimeWorkspaceRevocation?: (workspaceId: string) => void;
}
export function useWorkspaceDangerZone(options: UseWorkspaceDangerZoneOptions) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const workspaceId = () => options.workspaceId();
  const currentUserId = () => options.currentUserId();
  const [showDelete, setShowDelete] = createSignal(false);
  const [deleting, setDeleting] = createSignal(false);
  const handleDelete = async () => {
    const id = workspaceId();
    if (!id) return;
    setDeleting(true);
    const previousWorkspaces = queryClient.getQueryData<WorkspacesListResponse>(["workspaces"]);
    try {
      await options.closePluginRuntimeByWorkspace?.(id, "workspace_deleted");
      discardWorkspaceSelection(id);
      const remainingWorkspaces = removeWorkspaceFromCache(id);
      setCurrentWorkspaceId(replacementWorkspaceId(remainingWorkspaces, id));
      await Promise.resolve();
      await deleteWorkspace(id);
      setShowDelete(false);
      navigate("/dashboard");
      await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    } catch (err) {
      options.releasePluginRuntimeWorkspaceRevocation?.(id);
      restoreWorkspaceCache(previousWorkspaces);
      setCurrentWorkspaceId(id);
      options.setError(err instanceof Error ? err.message : "Failed to delete");
    } finally {
      setDeleting(false);
    }
  };
  const [showLeave, setShowLeave] = createSignal(false);
  const [leaving, setLeaving] = createSignal(false);
  const handleLeave = async () => {
    const id = workspaceId();
    const userId = currentUserId();
    if (!id || !userId) return;
    setLeaving(true);
    const previousWorkspaces = queryClient.getQueryData<WorkspacesListResponse>(["workspaces"]);
    try {
      await options.closePluginRuntimeByWorkspace?.(id, "workspace_left");
      await removeWorkspaceMemberWithKeyDirectory(id, userId);
      discardWorkspaceSelection(id);
      const remainingWorkspaces = removeWorkspaceFromCache(id);
      setCurrentWorkspaceId(replacementWorkspaceId(remainingWorkspaces, id));
      setShowLeave(false);
      navigate("/dashboard");
      await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    } catch (err) {
      options.releasePluginRuntimeWorkspaceRevocation?.(id);
      restoreWorkspaceCache(previousWorkspaces);
      setCurrentWorkspaceId(id);
      options.setError(err instanceof Error ? err.message : "Failed to leave");
    } finally {
      setLeaving(false);
    }
  };
  return {
    triggerKekRotation: options.triggerKekRotation,
    showDelete,
    setShowDelete,
    deleting,
    handleDelete,
    showLeave,
    setShowLeave,
    leaving,
    handleLeave,
  };

  function removeWorkspaceFromCache(workspaceId: string): WorkspacesListResponse | undefined {
    const previous = queryClient.getQueryData<WorkspacesListResponse>(["workspaces"]);
    if (!previous) return undefined;
    queryClient.setQueryData<WorkspacesListResponse>(["workspaces"], {
      ...previous,
      workspaces: previous.workspaces.filter((workspace) => workspace.id !== workspaceId),
    });
    return previous;
  }

  function restoreWorkspaceCache(previous: WorkspacesListResponse | undefined): void {
    if (!previous) return;
    queryClient.setQueryData<WorkspacesListResponse>(["workspaces"], previous);
  }
}

function replacementWorkspaceId(
  workspaces: WorkspacesListResponse | undefined,
  removedWorkspaceId: string,
): string | null {
  const candidates = workspaces?.workspaces.filter(
    (workspace) => workspace.id !== removedWorkspaceId,
  );
  if (!candidates || candidates.length === 0) return null;
  return candidates.find((workspace) => workspace.is_default)?.id ?? candidates[0].id;
}
