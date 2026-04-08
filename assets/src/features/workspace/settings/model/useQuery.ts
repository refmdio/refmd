import { createQuery } from "@tanstack/solid-query";
import type { Accessor } from "solid-js";
import { getWorkspace } from "../lib/crud";

export function useWorkspaceQuery(workspaceId: Accessor<string | null | undefined>) {
  const currentWorkspaceId = () => workspaceId();

  return createQuery(() => ({
    queryKey: ["workspace", currentWorkspaceId()],
    queryFn: () => getWorkspace(currentWorkspaceId()!),
    enabled: !!currentWorkspaceId(),
  }));
}
