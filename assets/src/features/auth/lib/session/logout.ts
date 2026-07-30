import { clearDocumentKeyCache } from "@/entities/document";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { authApi } from "@/shared/api";
import {
  clearAllPersistedKeys,
  clearPlaintextActivityMetadata,
  clearSessionData,
} from "@/shared/lib/auth/key-persistence";
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
import { setSecureLogoutIncomplete } from "@/shared/lib/auth/logout-incomplete";

interface LogoutResult {
  logoutIncomplete: boolean;
  redirectPath: string;
}

export async function performLogout(keepCredentials: boolean): Promise<LogoutResult> {
  const shareScopedLogout = getPreferredSessionScope() === "share" && keepCredentials;
  const hasUserSession = !!authState();
  const worker = getCryptoWorker();
  let logoutIncomplete = false;

  if (!keepCredentials) {
    if (!(await runLogoutStep(() => worker.lock()))) {
      logoutIncomplete = true;
    }
    terminateCryptoWorker();
    terminateAllScopedCryptoWorkers();
  }

  const beforeCleanup = await runBeforeSessionCleanup({ secure: !keepCredentials });
  logoutIncomplete ||= beforeCleanup.failures.length > 0;

  if (keepCredentials) {
    if (!(await runLogoutStep(() => worker.lock()))) {
      logoutIncomplete = true;
    }
    terminateCryptoWorker();
    terminateAllScopedCryptoWorkers();
  }
  resetPhoenixConnection();

  if (!shareScopedLogout) {
    if (!(await runLogoutStep(clearPlaintextActivityMetadata))) {
      logoutIncomplete = true;
    }
    clearDocumentKeyCache();
    runSessionCleanup();
    clearSession();
    setCurrentWorkspaceId(null);
  }

  if (!shareScopedLogout && !keepCredentials) {
    if (!(await runLogoutStep(clearStoredShareParticipantSessions))) {
      logoutIncomplete = true;
    }

    if (!(await runLogoutStep(clearAllPersistedKeys))) {
      logoutIncomplete = true;
    }
  }

  if (!shareScopedLogout && !keepCredentials) {
    if (
      !(await runLogoutStep(() =>
        authApi.logout({ clearMountSession: true, sessionScope: "share" }),
      ))
    ) {
      logoutIncomplete = true;
    }
  }

  if (!shareScopedLogout || !keepCredentials) {
    if (
      !(await runLogoutStep(() =>
        authApi.logout(
          shareScopedLogout
            ? { clearMountSession: !keepCredentials, sessionScope: "share" }
            : { clearMountSession: !keepCredentials },
        ),
      ))
    ) {
      logoutIncomplete = true;
    }
  }

  if (shareScopedLogout) {
    if (!keepCredentials) {
      if (!(await runLogoutStep(clearShareParticipantState))) {
        logoutIncomplete = true;
      }
    }

    if (!keepCredentials) {
      setPreferredSessionScope(null);
    }
    clearDocumentKeyCache();

    if (hasUserSession) {
      if (!(await runLogoutStep(restoreSessionContext))) {
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

  if (!(await runLogoutStep(() => clearSessionData({ preserveAuthBootstrap: keepCredentials })))) {
    logoutIncomplete = true;
  }

  if (!keepCredentials) {
    if (!(await runLogoutStep(clearAllPersistedKeys))) {
      logoutIncomplete = true;
    }
  }

  if (!keepCredentials) {
    setPreferredSessionScope(null);
    setSecureLogoutIncomplete(logoutIncomplete);
  }
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

async function runLogoutStep(step: () => unknown): Promise<boolean> {
  try {
    await step();
    return true;
  } catch {
    return false;
  }
}
