import {
  getTotalCacheSize,
  getEvictionCandidates,
  deleteDocumentOfflineData,
  deleteOrphanedKeks,
  getAllOfflineDocumentMetas,
  getOfflineDocumentMeta,
  putOfflineDocumentMeta,
} from "../storage/store";

const MAX_CACHE_SIZE_BROWSER = 100 * 1024 * 1024; // 100 MB
const MAX_CACHE_SIZE_DESKTOP = 1024 * 1024 * 1024; // 1 GB

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI__" in window;
}

function getMaxCacheSize(): number {
  return isTauri() ? MAX_CACHE_SIZE_DESKTOP : MAX_CACHE_SIZE_BROWSER;
}

export async function checkAndEvict(): Promise<void> {
  try {
    const totalSize = await getTotalCacheSize();
    const maxSize = getMaxCacheSize();

    if (totalSize <= maxSize) return;

    const overshoot = totalSize - maxSize;
    const estimateCount = Math.max(5, Math.ceil(overshoot / (1024 * 1024)));
    const candidates = await getEvictionCandidates(estimateCount);

    for (const documentId of candidates) {
      await deleteDocumentOfflineData(documentId);
      // Reset cacheSize in metadata (metadata is preserved for listing)
      const meta = await getOfflineDocumentMeta(documentId);
      if (meta) {
        meta.cacheSize = 0;
        await putOfflineDocumentMeta(meta);
      }

      const newTotal = await getTotalCacheSize();
      if (newTotal <= maxSize) break;
    }

    await cleanupOrphanedKeks();

    // Check if still over limit after eviction
    const finalSize = await getTotalCacheSize();
    if (finalSize > maxSize) {
      import("@/shared/lib/notice")
        .then(
          ({ Notice }) =>
            new Notice(
              "Offline cache storage is full. Some documents may not be available offline.",
            ),
        )
        .catch(() => {});
    }
  } catch (err) {
    console.warn("[lru-eviction] Error during eviction:", err);
  }
}

async function cleanupOrphanedKeks(): Promise<void> {
  const metas = await getAllOfflineDocumentMetas();
  const activeWorkspaceIds = metas.filter((m) => m.cacheSize > 0).map((m) => m.workspaceId);
  await deleteOrphanedKeks(activeWorkspaceIds);
}
