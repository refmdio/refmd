import { createEffect } from "solid-js";
import type { QueryClient } from "@tanstack/solid-query";
import { performKekRotation } from "@/features/devices";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";

interface PendingWorkspaceRotation {
  workspace_id: string;
  current_kek_version: number;
  kek_rotation_initiator_user_id: string | null;
}

const attemptedRotations = new Set<string>();

export function useWorkspaceKekRotationMonitor(
  workspacesNeedingRotation: () => PendingWorkspaceRotation[],
  queryClient: QueryClient,
): void {
  createEffect(() => {
    const pending = workspacesNeedingRotation();
    if (pending.length === 0) return;

    const auth = authState();
    const device = deviceState();
    if (!cryptoWorkerReady() || !auth || !device?.deviceId) return;

    const initiatorWorkspaces = pending.filter(
      (workspace) =>
        workspace.kek_rotation_initiator_user_id === auth.user.id &&
        !attemptedRotations.has(workspace.workspace_id),
    );
    if (initiatorWorkspaces.length === 0) return;

    for (const workspace of initiatorWorkspaces) {
      attemptedRotations.add(workspace.workspace_id);
    }

    performKekRotation(initiatorWorkspaces, auth.user.id, device.deviceId)
      .then(() => {
        for (const workspace of initiatorWorkspaces) {
          attemptedRotations.delete(workspace.workspace_id);
        }
        void queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      })
      .catch(() => {
        for (const workspace of initiatorWorkspaces) {
          attemptedRotations.delete(workspace.workspace_id);
        }
      });
  });
}
