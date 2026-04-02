import { createSignal, onMount } from "solid-js";
import {
  restoreOfflineSession,
  restoreSession,
  type OfflineSessionResult,
  type SessionRestoreResult,
} from "@/features/auth";
import {
  setAuthState,
  setCryptoWorkerReady,
  setDeviceState,
  setFullSession,
  setTofuErrors,
} from "@/entities/session";
import { isTofuHardFail } from "@/shared/lib/crypto/worker/client";

export function isPublicPath(pathname = window.location.pathname): boolean {
  return (
    pathname.startsWith("/auth/") ||
    pathname === "/devices/register" ||
    pathname.startsWith("/invite")
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
    identitySigningPublic: null,
    identityEcdhPublic: null,
    expiresAt: "",
  });
  setDeviceState({
    deviceId: offlineResult.deviceId,
    deviceSigningPublic: offlineResult.deviceSigningPublic,
    deviceEcdhPublic: offlineResult.deviceEcdhPublic,
  });
  // DSK is set even if !workerReady (no UMK). Offline operations
  // (unwrapDekFromOffline, decryptOfflineCache) only need DSK.
  setCryptoWorkerReady(true);
}

function applyRestoredSession(result: SessionRestoreResult): void {
  const auth = {
    user: { id: result.userId, email: result.email, name: result.name },
    sessionId: result.sessionId,
    identitySigningPublic: result.identitySigningPublic,
    identityEcdhPublic: result.identityEcdhPublic,
    expiresAt: result.expiresAt,
    needsPasswordReentry: result.needsPasswordReentry,
  };

  if (result.deviceId && result.deviceSigningPublic) {
    setFullSession(auth, {
      deviceId: result.deviceId,
      deviceSigningPublic: result.deviceSigningPublic,
      deviceEcdhPublic: result.deviceEcdhPublic,
    });
  } else {
    setAuthState(auth);
    if (result.deviceId) {
      setDeviceState({
        deviceId: result.deviceId,
        deviceSigningPublic: null,
        deviceEcdhPublic: null,
      });
    }
  }

  if (result.workerReady) {
    setCryptoWorkerReady(true);
  }

  if (result.tofuWarnings.length > 0) {
    setTofuErrors(result.tofuWarnings);
  }
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
          }
        }
        return;
      }

      applyRestoredSession(result);

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
