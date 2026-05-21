import { createQuery } from "@tanstack/solid-query";
import type { Accessor } from "solid-js";
import { authState, deviceState } from "@/entities/session";
import { getWorkspace } from "../../lib/settings/crud";

export function useWorkspaceQuery(workspaceId: Accessor<string | null | undefined>) {
  const currentWorkspaceId = () => workspaceId();

  return createQuery(() => ({
    queryKey: ["workspace", currentWorkspaceId()],
    queryFn: () => getWorkspace(currentWorkspaceId()!),
    enabled: !!authState() && !!deviceState() && !!currentWorkspaceId(),
  }));
}
