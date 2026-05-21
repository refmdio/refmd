import { clearDocumentKeyCache } from "@/entities/document";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { authApi } from "@/shared/api";
import { clearAllPersistedKeys, clearSessionData } from "@/shared/lib/auth/key-persistence";
import { clearStoredShareParticipantSessions } from "@/shared/lib/auth/share-participant-session-store";
import { authState, clearSession, restoreSessionContext } from "@/entities/session";
import { runBeforeSessionCleanup, runSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { getCryptoWorker, terminateCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { terminateAllScopedCryptoWorkers } from "@/shared/lib/crypto/worker/scoped";
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

  await runBeforeSessionCleanup({ secure: !keepCredentials });

  try {
    await worker.lock();
  } catch {
    // Worker may not be initialized.
  }
  terminateCryptoWorker();
  terminateAllScopedCryptoWorkers();
  resetPhoenixConnection();

  let logoutIncomplete = false;

  if (!shareScopedLogout && !keepCredentials) {
    try {
      await clearAllPersistedKeys();
      await clearShareParticipantState();
    } catch {
      logoutIncomplete = true;
    }
  }

  if (!shareScopedLogout && !keepCredentials) {
    try {
      await authApi.logout({ clearMountSession: true, sessionScope: "share" });
    } catch {
      // A user may not have an active share session cookie.
    }
  }

  if (!shareScopedLogout || !keepCredentials) {
    try {
      await authApi.logout(
        shareScopedLogout
          ? { clearMountSession: !keepCredentials, sessionScope: "share" }
          : { clearMountSession: !keepCredentials },
      );
    } catch {
      logoutIncomplete = true;
    }
  }

  if (shareScopedLogout) {
    if (!keepCredentials) {
      try {
        await clearShareParticipantState();
      } catch {
        logoutIncomplete = true;
      }
    }

    if (!keepCredentials) {
      setPreferredSessionScope(null);
    }
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
    await clearSessionData({ preserveAuthBootstrap: keepCredentials });
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

async function clearShareParticipantState(): Promise<void> {
  await Promise.all([
    clearStoredShareParticipantSessions(),
    getCryptoWorker().clearMountTrustAnchorsWithDsk(),
  ]);
}
