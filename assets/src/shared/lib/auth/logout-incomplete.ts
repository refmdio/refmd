import { clearAllPersistedKeys, clearSessionData } from "./key-persistence";
import { ApiError, authApi } from "@/shared/api";
import { runBeforeSessionCleanup, runSessionCleanup } from "./session-cleanup";
import { getCryptoWorker, terminateCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { terminateAllScopedCryptoWorkers } from "@/shared/lib/crypto/worker/scoped";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";

const LOGOUT_INCOMPLETE_KEY = "logout-incomplete";

export function setSecureLogoutIncomplete(incomplete: boolean): void {
  if (incomplete) {
    localStorage.setItem(LOGOUT_INCOMPLETE_KEY, "true");
  } else {
    localStorage.removeItem(LOGOUT_INCOMPLETE_KEY);
  }
}

export function isSecureLogoutIncomplete(): boolean {
  return localStorage.getItem(LOGOUT_INCOMPLETE_KEY) === "true";
}

export async function retrySecureLogoutCleanup(): Promise<void> {
  let cleanupFailed = false;

  try {
    await getCryptoWorker().lock();
  } catch {
    cleanupFailed = true;
  }
  terminateCryptoWorker();
  terminateAllScopedCryptoWorkers();

  const beforeCleanup = await runBeforeSessionCleanup({ secure: true });
  cleanupFailed ||= beforeCleanup.failures.length > 0;
  resetPhoenixConnection();
  runSessionCleanup();

  const logoutResults = await Promise.allSettled([
    invalidateServerSession("share"),
    invalidateServerSession("user"),
  ]);
  if (logoutResults.some((result) => result.status === "rejected")) {
    cleanupFailed = true;
  }

  const persistenceResults = await Promise.allSettled([
    clearSessionData({ preserveAuthBootstrap: false }),
    clearAllPersistedKeys(),
  ]);
  if (persistenceResults.some((result) => result.status === "rejected")) {
    cleanupFailed = true;
  }
  if (cleanupFailed) throw new Error("secure_logout_cleanup_incomplete");

  setSecureLogoutIncomplete(false);
}

async function invalidateServerSession(scope: "user" | "share"): Promise<void> {
  try {
    await authApi.logout(
      scope === "share"
        ? { clearMountSession: true, sessionScope: "share" }
        : { clearMountSession: true },
    );
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return;
    throw error;
  }
}
