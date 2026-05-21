import { createSignal, onMount } from "solid-js";
import {
  applyRestoredSessionState,
  restoreOfflineSession,
  restoreSession,
  type OfflineSessionResult,
} from "@/features/auth";
import {
  clearSession,
  setAuthState,
  setCryptoWorkerReady,
  setDeviceState,
  setSessionContextRestorer,
  setTofuErrors,
} from "@/entities/session";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { isTofuHardFail } from "@/shared/lib/crypto/worker/client";

export function isPublicPath(pathname = window.location.pathname): boolean {
  return (
    pathname.startsWith("/auth/") ||
    pathname === "/devices/register" ||
    pathname.startsWith("/invite") ||
    pathname.startsWith("/share/")
  );
}

function applyOfflineSession(offlineResult: OfflineSessionResult) {
  setAuthState({
    user: {
      id: offlineResult.userId,
      email: offlineResult.email,
      name: offlineResult.name,
    },
    sessionId: "",
    identityHybridSigningPublicKeyMaterial: null,
    identityEcdhPublic: null,
    expiresAt: "",
  });
  setDeviceState({
    deviceId: offlineResult.deviceId,
    deviceSigningKeyId: offlineResult.deviceSigningKeyId,
    deviceHybridSigningPublicKeyMaterial: offlineResult.deviceHybridSigningPublicKeyMaterial,
    deviceEcdhPublic: offlineResult.deviceEcdhPublic,
  });
  // DSK is set even if !workerReady (no UMK). Offline operations
  // (restoreDekFromOffline, decryptOfflineCache) only need DSK.
  setCryptoWorkerReady(true);
}

export function useSessionBootstrap() {
  const [ready, setReady] = createSignal(false);
  const [showPasswordReentry, setShowPasswordReentry] = createSignal(false);
  const [transientError, setTransientError] = createSignal<string | null>(null);

  const attemptRestore = async () => {
    setTransientError(null);

    try {
      const result = await restoreSession();
      if (result === "rate_limited") {
        setTransientError("Too many requests. Please wait a moment and try again.");
        return;
      }

      if (result === "transient_error") {
        const offlineResult = await restoreOfflineSession();
        if (offlineResult) {
          applyOfflineSession(offlineResult);
        } else {
          setTransientError(
            "Could not connect to the server. Please check your connection and try again.",
          );
        }
        return;
      }

      if (!result) {
        const { offlineMode } = await import("@/shared/lib/offline/offline-state");
        if (offlineMode()) {
          const offlineResult = await restoreOfflineSession();
          if (offlineResult) {
            applyOfflineSession(offlineResult);
            return;
          }
        }
        clearSession();
        setCurrentWorkspaceId(null);
        return;
      }

      applyRestoredSessionState(result);

      if (result.needsPasswordReentry) {
        setShowPasswordReentry(true);
      }

      if (!result.deviceVerified && !result.needsPasswordReentry && !isPublicPath()) {
        window.location.replace("/devices/register");
        return;
      }
    } catch (error) {
      if (isTofuHardFail(error)) {
        setTofuErrors([error.message]);
      } else {
        setTransientError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setReady(true);
    }
  };

  setSessionContextRestorer(async () => {
    const result = await restoreSession();
    if (!result || result === "rate_limited" || result === "transient_error") {
      if (!result) {
        clearSession();
        setCurrentWorkspaceId(null);
      }
      return;
    }

    applyRestoredSessionState(result);
  });

  onMount(() => {
    void attemptRestore();
  });

  return {
    ready,
    showPasswordReentry,
    transientError,
    retryRestore: async () => {
      setReady(false);
      await attemptRestore();
    },
    closePasswordReentry: () => setShowPasswordReentry(false),
  };
}
