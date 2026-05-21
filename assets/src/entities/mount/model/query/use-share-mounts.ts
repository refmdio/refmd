import { createQuery } from "@tanstack/solid-query";
import { sharesApi } from "@/shared/api";
import { authState, deviceState } from "@/entities/session";
import { shouldPreferOfflineCache } from "@/shared/lib/offline/offline-state";
import type { ShareMount } from "../mount/types";

export type ResolvedShareMount = ShareMount & { resolved_title?: string };

export function useShareMounts(workspaceId: () => string | null | undefined) {
  const isGuest = () => authState()?.user.accountType === "guest";
  const query = createQuery(() => ({
    queryKey: ["share-mounts", workspaceId()],
    queryFn: async () => {
      if (shouldPreferOfflineCache()) {
        return { mounts: [] };
      }
      const currentWorkspaceId = workspaceId()!;
      const response = await sharesApi.listShareMounts(currentWorkspaceId);
      return {
        mounts: response.mounts.map((mount) => ({
          ...mount,
          workspace_id: currentWorkspaceId,
        })),
      };
    },
    enabled: !!authState() && !!deviceState() && !!workspaceId() && !isGuest(),
  }));

  const mounts = () => query.data?.mounts ?? [];

  return { query, mounts };
}
