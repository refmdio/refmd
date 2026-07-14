import { createEffect } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { workspacesApi } from "@/shared/api";
import { authState, deviceState } from "@/entities/session";
import { currentWorkspaceId, setCurrentWorkspaceId } from "../selection/selection";
import { putOfflineWorkspaces } from "@/shared/lib/offline/storage/store";
import { verifyAndPinAuditCheckpoint } from "@/shared/lib/anti-rollback/audit-checkpoint-pin";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { clientError } from "@/shared/lib/logger";

export async function fetchVerifiedWorkspaces() {
  const deviceId = deviceState()?.deviceId;
  if (!deviceId) throw new Error("workspace_query_device_required");

  const result = await workspacesApi.list();
  await Promise.all(
    result.workspaces.map(async (workspace) => {
      try {
        await fetchVerifiedKeyDirectory({
          scopeKind: "workspace",
          scopeId: workspace.id,
          rrpDeviceId: deviceId,
        });
        await verifyAndPinAuditCheckpoint(workspace.audit_checkpoint);
      } catch (error) {
        clientError("workspace_verification_failed", { error, workspaceId: workspace.id });
        throw error;
      }
    }),
  );
  putOfflineWorkspaces(
    result.workspaces.map((ws) => ({
      id: ws.id,
      name: ws.name,
      description: ws.description ?? "",
      slug: ws.slug,
      isDefault: ws.is_default ?? false,
      updatedAt: ws.updated_at,
      lastSyncedAt: Date.now(),
    })),
  ).catch(() => {});
  return result;
}

export function useWorkspaces() {
  const query = createQuery(() => ({
    queryKey: ["workspaces"],
    queryFn: fetchVerifiedWorkspaces,
    enabled: !!authState() && !!deviceState(),
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
        current_user_base_role: ws.current_user_base_role ?? null,
      }));

  const allWorkspaces = () => query.data?.workspaces ?? [];

  return { workspaces: workspaceList, allWorkspaces, workspacesNeedingRotation, query };
}
