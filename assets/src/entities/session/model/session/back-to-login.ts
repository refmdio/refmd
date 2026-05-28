import { authApi } from "@/shared/api";
import { clearPersistedLoginKeyMaterial } from "@/shared/lib/auth/key-persistence";
import { terminateCryptoWorker } from "@/shared/lib/crypto/worker/client";
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

  resetPhoenixConnection();
  terminateCryptoWorker();
  clearSession();

  try {
    await clearPersistedLoginKeyMaterial();
  } catch {
    // Login must remain reachable even if best-effort browser cleanup fails.
  }

  window.location.replace("/auth/login");
}
