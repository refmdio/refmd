import { createQuery } from "@tanstack/solid-query";
import type { ShareMountLookupItem } from "@/entities/mount";
import { sharesApi } from "@/shared/api";

export function useShareMountLookup(options: {
  shareSlug: () => string;
  enabled: () => boolean;
  initialMounts?: () => ShareMountLookupItem[] | undefined;
}) {
  const query = createQuery(() => ({
    queryKey: ["share-mounts-for-share", options.shareSlug()],
    queryFn: () => sharesApi.listShareMountsForShare(options.shareSlug()),
    enabled: options.enabled() && options.initialMounts?.() == null,
  }));

  const mounts = () => options.initialMounts?.() ?? query.data?.mounts ?? [];

  return {
    mounts,
    refetch: query.refetch,
  };
}
