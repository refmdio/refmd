import { clearDocumentKeyCache } from "@/entities/document";
import { clearSession } from "@/entities/session";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { clearAllPersistedKeys, clearSessionData } from "@/shared/lib/auth/key-persistence";
import { setSecureLogoutIncomplete } from "@/shared/lib/auth/logout-incomplete";
import { runSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { getCryptoWorker, terminateCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { terminateAllScopedCryptoWorkers } from "@/shared/lib/crypto/worker/scoped";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";

export async function wipePredecessorDeviceBeforeIdentityRecovery(): Promise<void> {
  setSecureLogoutIncomplete(true);

  await getCryptoWorker()
    .lock()
    .catch(() => {});
  terminateCryptoWorker();
  terminateAllScopedCryptoWorkers();
  resetPhoenixConnection();
  clearDocumentKeyCache();
  runSessionCleanup();
  clearSession();
  setCurrentWorkspaceId(null);

  const cleanupResults = await Promise.allSettled([
    clearSessionData({ preserveAuthBootstrap: false }),
    clearAllPersistedKeys(),
  ]);
  if (cleanupResults.some((result) => result.status === "rejected")) {
    throw new Error("identity_recovery_local_wipe_incomplete");
  }
  setSecureLogoutIncomplete(false);
}
