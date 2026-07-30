import { authApi } from "@/shared/api";
import {
  clearPlaintextActivityMetadata,
  clearSessionData,
} from "@/shared/lib/auth/key-persistence";
import { runBeforeSessionCleanup, runSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { terminateCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { terminateAllScopedCryptoWorkers } from "@/shared/lib/crypto/worker/scoped";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";
import { authState, clearSession } from "../auth/state";

export async function returnToLogin(): Promise<void> {
  if (authState()) {
    try {
      await authApi.logout({ clearMountSession: false });
    } catch {
      // Local cleanup still has to make the login route reachable.
    }
  }

  await runBeforeSessionCleanup({ secure: false });
  resetPhoenixConnection();
  terminateCryptoWorker();
  terminateAllScopedCryptoWorkers();
  runSessionCleanup();
  clearSession();
  clearPlaintextActivityMetadata();
  await clearSessionData({ preserveAuthBootstrap: true });

  window.location.replace("/auth/login");
}
