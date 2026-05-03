import { createQuery } from "@tanstack/solid-query";
import { sharesApi } from "@/shared/api";
import { shouldPreferOfflineCache } from "@/shared/lib/offline/offline-state";
import type { ShareMountDetail } from "./types";

export function useShareMounts(workspaceId: () => string | null | undefined) {
  const query = createQuery(() => ({
    queryKey: ["share-mounts", workspaceId()],
    queryFn: async () => {
      if (shouldPreferOfflineCache()) {
        return { mounts: [] };
      }
      return await sharesApi.listShareMounts(workspaceId()!);
    },
    enabled: !!workspaceId(),
  }));

  const mounts = () => query.data?.mounts ?? [];

  return { query, mounts };
}

export async function deleteShareMount(mountId: string): Promise<void> {
  await sharesApi.deleteShareMount(mountId);
}

export async function getShareMount(
  mountId: string,
  options?: { documentId?: string | null; shareId?: string | null },
): Promise<ShareMountDetail> {
  return sharesApi.getShareMount(mountId, options);
}

export async function getShareMountFolder(mountId: string, folderToken: string) {
  return sharesApi.getShareMountFolder(mountId, folderToken);
}
