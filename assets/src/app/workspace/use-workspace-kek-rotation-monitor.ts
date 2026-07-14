import { createEffect, createSignal, onCleanup } from "solid-js";
import type { QueryClient } from "@tanstack/solid-query";
import { performKekRotation } from "@/features/devices";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";

interface PendingWorkspaceRotation {
  workspace_id: string;
  current_kek_version: number;
  kek_rotation_initiator_user_id: string | null;
  current_user_base_role: string | null;
}

const ROTATION_RETRY_DELAY_MS = 1_000;

export function createRotationRetryScheduler(
  onRetry: () => void,
  delayMs = ROTATION_RETRY_DELAY_MS,
): { schedule: () => void; cancel: () => void; dispose: () => void; pending: () => boolean } {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let disposed = false;
  return {
    schedule: () => {
      if (disposed || timer) return;
      timer = setTimeout(() => {
        timer = null;
        onRetry();
      }, delayMs);
    },
    cancel: () => {
      if (timer) clearTimeout(timer);
      timer = null;
    },
    dispose: () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      timer = null;
    },
    pending: () => timer !== null,
  };
}

export function useWorkspaceKekRotationMonitor(
  workspacesNeedingRotation: () => PendingWorkspaceRotation[],
  queryClient: QueryClient,
): void {
  const attemptedRotations = new Set<string>();
  const [retryRevision, setRetryRevision] = createSignal(0);
  const retry = createRotationRetryScheduler(() => {
    void queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    setRetryRevision((value) => value + 1);
  });
  onCleanup(() => {
    attemptedRotations.clear();
    retry.dispose();
  });

  createEffect(() => {
    retryRevision();
    const pending = workspacesNeedingRotation();
    if (pending.length === 0) {
      retry.cancel();
      return;
    }

    const auth = authState();
    const device = deviceState();
    if (!cryptoWorkerReady() || !auth || !device?.deviceId) return;

    const initiatorWorkspaces = pending.filter(
      (workspace) =>
        canInitiateWorkspaceRotation(workspace, auth.user.id) &&
        !attemptedRotations.has(workspace.workspace_id),
    );
    if (initiatorWorkspaces.length === 0) return;

    for (const workspace of initiatorWorkspaces) {
      attemptedRotations.add(workspace.workspace_id);
    }

    performKekRotation(initiatorWorkspaces, auth.user.id, device.deviceId)
      .then(() => {
        retry.cancel();
        for (const workspace of initiatorWorkspaces) {
          attemptedRotations.delete(workspace.workspace_id);
        }
        void queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      })
      .catch(() => {
        for (const workspace of initiatorWorkspaces) {
          attemptedRotations.delete(workspace.workspace_id);
        }
        const pendingIds = new Set(
          workspacesNeedingRotation().map((workspace) => workspace.workspace_id),
        );
        if (initiatorWorkspaces.some((workspace) => pendingIds.has(workspace.workspace_id))) {
          retry.schedule();
        }
      });
  });
}

export function canInitiateWorkspaceRotation(
  workspace: PendingWorkspaceRotation,
  userId: string,
): boolean {
  if (workspace.kek_rotation_initiator_user_id === userId) return true;
  if (workspace.kek_rotation_initiator_user_id !== null) return false;
  return (
    workspace.current_user_base_role === "owner" || workspace.current_user_base_role === "admin"
  );
}
