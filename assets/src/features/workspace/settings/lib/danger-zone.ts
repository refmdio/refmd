import { createSignal, type Accessor } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import type { WorkspaceRotationInfo } from "@/shared/api/devices";
import { setCurrentWorkspaceId } from "@/entities/workspace";
type TriggerKekRotationFn = (rotationList: WorkspaceRotationInfo[]) => Promise<void>;
import { deleteWorkspace, removeWorkspaceMember } from "./crud";
interface UseWorkspaceDangerZoneOptions {
  workspaceId: Accessor<string | null | undefined>;
  currentUserId: Accessor<string | undefined>;
  setError: (value: string | null) => void;
  triggerKekRotation: TriggerKekRotationFn;
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
    try {
      await deleteWorkspace(id);
      setCurrentWorkspaceId(null);
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      setShowDelete(false);
      navigate("/dashboard");
    } catch (err) {
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
    try {
      await removeWorkspaceMember(id, userId);
      setCurrentWorkspaceId(null);
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      setShowLeave(false);
      navigate("/dashboard");
    } catch (err) {
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
}
