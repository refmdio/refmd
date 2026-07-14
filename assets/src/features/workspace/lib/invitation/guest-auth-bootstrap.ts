import type { CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";

interface GuestAuthBootstrapParams {
  userId: string;
  email: string;
  name: string;
  deviceId: string;
  deviceSigningKeyId: string;
}

export async function persistGuestAuthBootstrap(
  worker: Pick<CryptoWorkerClient, "storeAuthBootstrap">,
  params: GuestAuthBootstrapParams,
  now: () => number = Date.now,
): Promise<void> {
  const stored = await worker.storeAuthBootstrap({
    ...params,
    cachedAt: now(),
  });

  if (!stored) {
    throw new Error("Guest session keys could not be prepared for reload.");
  }
}
