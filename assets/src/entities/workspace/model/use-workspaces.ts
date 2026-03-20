import { createEffect } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { workspacesApi } from "@/shared/api";
import { authState, cryptoWorkerReady } from "@/shared/lib/auth-state";
import { currentWorkspaceId, setCurrentWorkspaceId } from "./workspace-selection";

export function useWorkspaces() {
  const query = createQuery(() => ({
    queryKey: ["workspaces"],
    queryFn: () => workspacesApi.list(),
    enabled: !!authState() && cryptoWorkerReady(),
  }));

  createEffect(() => {
    const wsList = query.data?.workspaces;
    if (!wsList || wsList.length === 0) return;
    const cur = currentWorkspaceId();
    if (!cur || !wsList.some((ws) => ws.id === cur)) {
      const defaultWs = wsList.find((ws) => ws.is_default);
      setCurrentWorkspaceId(defaultWs ? defaultWs.id : wsList[0].id);
    }
  });

  const workspaceList = () =>
    (query.data?.workspaces ?? []).map((ws) => ({
      id: ws.id,
      name: ws.name,
    }));

  const workspacesNeedingRotation = () =>
    (query.data?.workspaces ?? [])
      .filter((ws) => ws.needs_kek_rotation)
      .map((ws) => ({
        workspace_id: ws.id,
        current_kek_version: ws.current_kek_version,
        kek_rotation_initiator_user_id: ws.kek_rotation_initiator_user_id ?? null,
      }));

  const allWorkspaces = () => query.data?.workspaces ?? [];

  return { workspaces: workspaceList, allWorkspaces, workspacesNeedingRotation, query };
}
