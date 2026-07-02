import { createEffect, onCleanup } from "solid-js";
import { currentWorkspaceId } from "@/entities/workspace";
import { getRateLimitRetryMs } from "@/shared/api";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";
import { documentEvents } from "@/app/bootstrap/document-manager";
import {
  buildDeviceKeyCaches,
  syncOfflineCreatedDocuments,
  syncPendingDocuments,
} from "@/features/editor";
import { distributeWorkspaceMemberEnvelopes } from "@/features/workspace";
import { clientWarn } from "@/shared/lib/logger";
import type { EventRef } from "@/shared/lib/events";

export function useOfflineSync(): void {
  let bgCacheCleanup: (() => void) | null = null;
  let bgCacheWorkspaceId: string | null = null;
  let documentCreateRef: EventRef | null = null;
  let offlineWatchCleanup: (() => void) | null = null;
  let offlineWatchPending = false;
  let offlineSyncTimer: ReturnType<typeof setTimeout> | null = null;
  let onlineCleanup: (() => void) | null = null;
  let offlineCreatedRetryTimer: ReturnType<typeof setInterval> | null = null;
  let offlineSyncInFlight = false;
  let offlineSyncQueued = false;
  let disposed = false;
  let syncGeneration = 0;

  function stopBackgroundCaching() {
    bgCacheCleanup?.();
    bgCacheCleanup = null;
    bgCacheWorkspaceId = null;
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
      const { offlineReason } = await import("@/shared/lib/offline/offline-state");
      const reason = offlineReason();
      const networkReachable = reason === "network" ? await canReachServer() : true;
      if (
        !isCurrentRun(workspaceId, generation) ||
        (reason === "network" && !networkReachable) ||
        reason === "server_unreachable" ||
        reason === "auth_backoff"
      ) {
        if (isCurrentRun(workspaceId, generation)) scheduleOfflineSync();
        return;
      }

      const { waitForGlobalRateLimit } = await import("@/shared/api/core");
      await waitForGlobalRateLimit();
      if (!isCurrentRun(workspaceId, generation)) return;

      const remainingOfflineCreated = await syncOfflineCreatedDocuments(workspaceId).catch(() => {
        // Per-document failures stay queued in IndexedDB, so dropping this aggregate rejection is
        // safe: the next scheduled sync run will retry the unsynced offline-created documents.
        return 1;
      });
      if (!isCurrentRun(workspaceId, generation)) return;

      let memberDistributionFailed = false;
      await distributeWorkspaceMemberEnvelopes(workspaceId).catch(() => {
        memberDistributionFailed = true;
        // Missing member envelopes are retried by the next scheduled sync pass.
      });
      if (!isCurrentRun(workspaceId, generation)) return;

      const pendingSyncAttempts = await syncPendingDocuments(workspaceId);
      if (!isCurrentRun(workspaceId, generation)) return;

      await ensureBackgroundCaching(workspaceId, generation);
      if (remainingOfflineCreated > 0) {
        scheduleOfflineSync(5_000);
      } else if (pendingSyncAttempts > 0 || memberDistributionFailed) {
        scheduleOfflineSync(10_000);
      }
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

  async function canReachServer(): Promise<boolean> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2_000);
    try {
      const response = await fetch("/health", {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
      });
      if (!response.ok) return false;
      const { clearAuthTransportNetworkFailure } =
        await import("@/shared/lib/ws/transport-coordinator");
      clearAuthTransportNetworkFailure();
      return true;
    } catch {
      return false;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function runOfflineCreatedReconnectSync(): Promise<void> {
    if (disposed) return;
    if (!cryptoWorkerReady()) return;
    const { getAllOfflineCreated } = await import("@/shared/lib/offline/storage/store");
    const entries = await getAllOfflineCreated().catch(() => []);
    if (!entries.some((entry) => !entry.syncBlockedReason)) return;
    if (!(await canReachServer())) return;
    const { waitForGlobalRateLimit } = await import("@/shared/api/core");
    await waitForGlobalRateLimit();
    if (disposed) return;
    await syncOfflineCreatedDocuments().catch((error) => {
      clientWarn("offline_created_reconnect_sync_failed", { error });
    });
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

  async function scheduleInitialOfflineSyncIfNeeded(
    workspaceId: string,
    generation: number,
  ): Promise<void> {
    const [{ getAllOfflineCreated, getAllPendingChanges }, { resolvePendingSyncTarget }] =
      await Promise.all([
        import("@/shared/lib/offline/storage/store"),
        import("@/features/editor/lib/offline/pending-sync"),
      ]);
    if (!isCurrentRun(workspaceId, generation)) return;

    const [offlineCreated, pendingChanges] = await Promise.all([
      getAllOfflineCreated().catch(() => []),
      getAllPendingChanges().catch(() => []),
    ]);
    if (!isCurrentRun(workspaceId, generation)) return;

    const hasOfflineCreated = offlineCreated.some(
      (entry) => entry.workspaceId === workspaceId && !entry.syncBlockedReason,
    );
    if (hasOfflineCreated) {
      scheduleOfflineSync();
      return;
    }

    for (const entry of pendingChanges) {
      if (entry.syncBlockedReason) continue;
      const target = await resolvePendingSyncTarget(entry.documentId).catch(() => null);
      if (!isCurrentRun(workspaceId, generation)) return;
      if (target?.workspaceId === workspaceId) {
        scheduleOfflineSync();
        return;
      }
    }
  }

  async function ensureBackgroundCaching(workspaceId: string, generation: number): Promise<void> {
    if (bgCacheCleanup && bgCacheWorkspaceId === workspaceId) return;

    stopBackgroundCaching();
    const { startBackgroundCaching } = await import("@/shared/lib/offline/cache/background");
    if (!isCurrentRun(workspaceId, generation)) return;
    bgCacheCleanup = startBackgroundCaching(
      workspaceId,
      buildDeviceKeyCaches,
      getKekResolverSession,
    );
    bgCacheWorkspaceId = workspaceId;
  }

  function ensureOfflineWatch() {
    if (offlineWatchCleanup || offlineWatchPending) return;

    offlineWatchPending = true;
    import("@/shared/lib/offline/offline-state")
      .then(({ offlineReason, onOfflineModeChange }) => {
        offlineWatchPending = false;
        if (disposed) return;

        offlineWatchCleanup = onOfflineModeChange((isOffline) => {
          const reason = offlineReason();
          if (!isOffline || reason === "ws_disconnect") scheduleOfflineSync(1_000);
        });
      })
      .catch(() => {
        offlineWatchPending = false;
      });
  }

  function ensureOnlineWatch() {
    if (onlineCleanup || typeof window === "undefined") return;
    const requestSync = () => {
      scheduleOfflineSync(1_000);
      for (const delay of [1_000, 3_000, 6_000]) {
        window.setTimeout(() => {
          void runOfflineCreatedReconnectSync();
        }, delay);
      }
    };
    window.addEventListener("online", requestSync);
    window.addEventListener("focus", requestSync);
    onlineCleanup = () => {
      window.removeEventListener("online", requestSync);
      window.removeEventListener("focus", requestSync);
    };
  }

  if (!documentCreateRef) {
    documentCreateRef = documentEvents.on("document-create", () => {
      stopBackgroundCaching();
      scheduleOfflineSync(1_000);
    });
  }

  ensureOnlineWatch();
  offlineCreatedRetryTimer = setInterval(() => {
    void runOfflineCreatedReconnectSync();
  }, 5_000);
  window.setTimeout(() => {
    void runOfflineCreatedReconnectSync();
  }, 3_000);

  createEffect(() => {
    const workspaceId = currentWorkspaceId();
    const workerReady = cryptoWorkerReady();

    syncGeneration += 1;
    offlineSyncQueued = false;
    clearOfflineSyncTimer();
    stopBackgroundCaching();

    if (!workspaceId || !workerReady || disposed) return;

    ensureOfflineWatch();
    void scheduleInitialOfflineSyncIfNeeded(workspaceId, syncGeneration);
  });

  onCleanup(() => {
    disposed = true;
    syncGeneration += 1;
    offlineSyncQueued = false;
    clearOfflineSyncTimer();
    stopBackgroundCaching();
    if (documentCreateRef) {
      documentEvents.offref(documentCreateRef);
      documentCreateRef = null;
    }
    offlineWatchCleanup?.();
    offlineWatchCleanup = null;
    onlineCleanup?.();
    onlineCleanup = null;
    if (offlineCreatedRetryTimer) {
      clearInterval(offlineCreatedRetryTimer);
      offlineCreatedRetryTimer = null;
    }
  });
}
