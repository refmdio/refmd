import { createEffect, onCleanup } from "solid-js";
import { currentWorkspaceId } from "@/entities/workspace";
import { getRateLimitRetryMs } from "@/shared/api";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";

export function useOfflineSync(): void {
  let bgCacheCleanup: (() => void) | null = null;
  let offlineWatchCleanup: (() => void) | null = null;
  let offlineWatchPending = false;
  let offlineSyncTimer: ReturnType<typeof setTimeout> | null = null;
  let offlineSyncInFlight = false;
  let offlineSyncQueued = false;
  let disposed = false;
  let syncGeneration = 0;

  function stopBackgroundCaching() {
    bgCacheCleanup?.();
    bgCacheCleanup = null;
  }

  function clearOfflineSyncTimer() {
    if (offlineSyncTimer) {
      clearTimeout(offlineSyncTimer);
      offlineSyncTimer = null;
    }
  }

  function isCurrentRun(workspaceId: string, generation: number): boolean {
    return (
      !disposed &&
      generation === syncGeneration &&
      currentWorkspaceId() === workspaceId &&
      cryptoWorkerReady()
    );
  }

  async function runOfflineSync(generation: number): Promise<void> {
    const workspaceId = currentWorkspaceId();
    if (!workspaceId || !cryptoWorkerReady() || disposed) return;
    if (offlineSyncInFlight) {
      offlineSyncQueued = true;
      return;
    }

    offlineSyncInFlight = true;
    try {
      const { offlineMode: isOffline } = await import("@/shared/lib/offline/offline-state");
      if (!isCurrentRun(workspaceId, generation) || isOffline()) return;

      const { waitForGlobalRateLimit } = await import("@/shared/api/core");
      await waitForGlobalRateLimit();
      if (!isCurrentRun(workspaceId, generation)) return;

      const { buildDeviceKeyCaches, syncOfflineCreatedDocuments, syncPendingDocuments } =
        await import("@/features/editor");
      await syncOfflineCreatedDocuments(workspaceId).catch(() => {
        // Per-document failures stay queued in IndexedDB, so dropping this aggregate rejection is
        // safe: the next scheduled sync run will retry the unsynced offline-created documents.
      });
      if (!isCurrentRun(workspaceId, generation)) return;

      await syncPendingDocuments(workspaceId);
      if (!isCurrentRun(workspaceId, generation)) return;

      stopBackgroundCaching();
      const { startBackgroundCaching } = await import("@/shared/lib/offline/background-cache");
      if (!isCurrentRun(workspaceId, generation)) return;
      bgCacheCleanup = startBackgroundCaching(
        workspaceId,
        buildDeviceKeyCaches,
        getKekResolverSession,
      );
    } catch (error) {
      const retryMs = getRateLimitRetryMs(error);
      if (retryMs !== null && isCurrentRun(workspaceId, generation)) {
        scheduleOfflineSync(retryMs);
        return;
      }
    } finally {
      offlineSyncInFlight = false;
      if (offlineSyncQueued) {
        offlineSyncQueued = false;
        scheduleOfflineSync();
      }
    }
  }

  function scheduleOfflineSync(delayMs = 3_000) {
    const workspaceId = currentWorkspaceId();
    if (!workspaceId || !cryptoWorkerReady() || disposed) return;
    const generation = syncGeneration;

    clearOfflineSyncTimer();
    offlineSyncTimer = setTimeout(() => {
      offlineSyncTimer = null;
      void runOfflineSync(generation);
    }, delayMs);
  }

  function ensureOfflineWatch() {
    if (offlineWatchCleanup || offlineWatchPending) return;

    offlineWatchPending = true;
    import("@/shared/lib/offline/offline-state")
      .then(({ onOfflineModeChange }) => {
        offlineWatchPending = false;
        if (disposed) return;

        offlineWatchCleanup = onOfflineModeChange((isOffline) => {
          if (!isOffline) scheduleOfflineSync(1_000);
        });
      })
      .catch(() => {
        offlineWatchPending = false;
      });
  }

  createEffect(() => {
    const workspaceId = currentWorkspaceId();
    const workerReady = cryptoWorkerReady();

    syncGeneration += 1;
    offlineSyncQueued = false;
    clearOfflineSyncTimer();
    stopBackgroundCaching();

    if (!workspaceId || !workerReady || disposed) return;

    ensureOfflineWatch();
    scheduleOfflineSync();
  });

  onCleanup(() => {
    disposed = true;
    syncGeneration += 1;
    offlineSyncQueued = false;
    clearOfflineSyncTimer();
    stopBackgroundCaching();
    offlineWatchCleanup?.();
    offlineWatchCleanup = null;
  });
}
