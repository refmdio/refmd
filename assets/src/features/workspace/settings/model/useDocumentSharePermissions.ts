import { createQuery } from "@tanstack/solid-query";
import type { Accessor } from "solid-js";
import { authState } from "@/entities/session";
import { checkEffectivePermission } from "@/entities/workspace";
import { workspacesApi } from "@/shared/api";
import { useWorkspaceQuery } from "./useQuery";

export function useDocumentSharePermissions(workspaceId: Accessor<string | null | undefined>) {
  const workspace = useWorkspaceQuery(workspaceId);
  const isRegisteredUser = () => authState()?.user.accountType !== "guest";
  const roles = createQuery(() => ({
    queryKey: ["workspace-roles", workspaceId()],
    queryFn: () => workspacesApi.listRoles(workspaceId()!),
    enabled: !!workspaceId() && isRegisteredUser(),
  }));

  const hasPermission = (permission: string) => {
    const roleId = workspace.data?.current_user_role_id;
    const roleList = roles.data?.roles;
    if (!roleId || !roleList) return false;
    return checkEffectivePermission(roleList, roleId, permission);
  };

  const registeredUserCan = (permission: string) => isRegisteredUser() && hasPermission(permission);

  return {
    canManageShares: () => registeredUserCan("document:write"),
    canDeleteShares: () => registeredUserCan("workspace:admin"),
    canPublishPublic: () => registeredUserCan("workspace:admin"),
  };
}
