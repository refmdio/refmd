import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export async function clearWrappedUmk(): Promise<void> {
  try {
    await getCryptoWorker().deleteWrappedUmkWithDsk();
  } catch {
    // Best effort
  }
}

export async function clearAuthBootstrap(): Promise<void> {
  try {
    await getCryptoWorker().deleteAuthBootstrapWithDsk();
  } catch {
    // Best effort
  }
}
