import { clearDocumentKeyCache } from "@/entities/document";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { authApi } from "@/shared/api";
import { clearAllPersistedKeys, clearSessionData } from "@/shared/lib/auth/key-persistence";
import { clearSession } from "@/entities/session";
import { getCryptoWorker, terminateCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";

interface LogoutResult {
  logoutIncomplete: boolean;
  redirectPath: string;
}

export async function performLogout(keepCredentials: boolean): Promise<LogoutResult> {
  try {
    await getCryptoWorker().lock();
  } catch {
    // Worker may not be initialized.
  }
  terminateCryptoWorker();
  resetPhoenixConnection();

  let logoutIncomplete = false;

  if (!keepCredentials) {
    try {
      await clearAllPersistedKeys();
    } catch {
      logoutIncomplete = true;
    }
  }

  try {
    await authApi.logout();
  } catch {
    logoutIncomplete = true;
  }

  try {
    await clearSessionData();
  } catch {
    logoutIncomplete = true;
  }
  clearDocumentKeyCache();
  clearSession();
  setCurrentWorkspaceId(null);

  return {
    logoutIncomplete,
    redirectPath: logoutIncomplete ? "/auth/login?logout_incomplete=true" : "/auth/login",
  };
}
