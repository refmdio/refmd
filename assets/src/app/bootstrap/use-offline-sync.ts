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

      const remainingOfflineCreated = await syncOfflineCreatedDocuments().catch(() => {
        // Per-document failures stay queued in IndexedDB, so dropping this aggregate rejection is
        // safe: the next scheduled sync run will retry the unsynced offline-created documents.
        return 1;
      });
      if (remainingOfflineCreated > 0 && isCurrentRun(workspaceId, generation)) {
        scheduleOfflineSync(5_000);
      }
      if (!isCurrentRun(workspaceId, generation)) return;

      await distributeWorkspaceMemberEnvelopes(workspaceId).catch(() => {
        // Missing member envelopes are retried by the next scheduled sync pass.
      });
      if (!isCurrentRun(workspaceId, generation)) return;
      scheduleOfflineSync(10_000);

      await syncPendingDocuments(workspaceId);
      if (!isCurrentRun(workspaceId, generation)) return;

      stopBackgroundCaching();
      const { startBackgroundCaching } = await import("@/shared/lib/offline/cache/background");
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

  async function canReachServer(): Promise<boolean> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2_000);
    try {
      await fetch("/api/auth/me", {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
      });
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
    scheduleOfflineSync();
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
