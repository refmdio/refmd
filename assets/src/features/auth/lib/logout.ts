import { clearDocumentKeyCache } from "@/entities/document";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { authApi } from "@/shared/api";
import { clearAllPersistedKeys, clearSessionData } from "@/shared/lib/auth/key-persistence";
import { deleteStoredShareParticipantSessionsForDevice } from "@/shared/lib/auth/share-participant-session-store";
import { authState, clearSession, restoreSessionContext } from "@/entities/session";
import { runSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { getCryptoWorker, terminateCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  getPreferredSessionScope,
  setPreferredSessionScope,
} from "@/shared/lib/auth/session-scope";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";

interface LogoutResult {
  logoutIncomplete: boolean;
  redirectPath: string;
}

export async function performLogout(keepCredentials: boolean): Promise<LogoutResult> {
  const shareScopedLogout = getPreferredSessionScope() === "share";
  const hasUserSession = !!authState();
  const worker = getCryptoWorker();
  let shareDeviceId: string | null = null;

  if (shareScopedLogout) {
    try {
      shareDeviceId = await worker.getDeviceId();
    } catch {
      shareDeviceId = null;
    }
  }

  try {
    await worker.lock();
  } catch {
    // Worker may not be initialized.
  }
  terminateCryptoWorker();
  resetPhoenixConnection();

  let logoutIncomplete = false;

  if (!shareScopedLogout && !keepCredentials) {
    try {
      await clearAllPersistedKeys();
    } catch {
      logoutIncomplete = true;
    }
  }

  try {
    await authApi.logout(shareScopedLogout ? { sessionScope: "share" } : undefined);
  } catch {
    logoutIncomplete = true;
  }

  if (shareScopedLogout) {
    try {
      if (!shareDeviceId) {
        throw new Error("share_device_id_unavailable");
      }

      await deleteStoredShareParticipantSessionsForDevice(shareDeviceId);
    } catch {
      logoutIncomplete = true;
    }

    setPreferredSessionScope(null);
    clearDocumentKeyCache();

    if (hasUserSession) {
      try {
        await restoreSessionContext();
      } catch {
        logoutIncomplete = true;
      }
    }

    const params = new URLSearchParams(window.location.search);
    if (logoutIncomplete) {
      params.set("logout_incomplete", "true");
    } else {
      params.delete("logout_incomplete");
    }

    const currentPath = `${window.location.pathname}${params.toString() ? `?${params}` : ""}`;

    return {
      logoutIncomplete,
      redirectPath: currentPath,
    };
  }

  try {
    await clearSessionData();
  } catch {
    logoutIncomplete = true;
  }
  clearDocumentKeyCache();
  runSessionCleanup();
  clearSession();
  setCurrentWorkspaceId(null);

  return {
    logoutIncomplete,
    redirectPath: logoutIncomplete ? "/auth/login?logout_incomplete=true" : "/auth/login",
  };
}
