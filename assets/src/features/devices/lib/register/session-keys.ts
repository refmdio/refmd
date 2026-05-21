import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export async function loadPersistedDskIntoWorker(): Promise<boolean> {
  return getCryptoWorker().loadStoredDsk();
}

export async function ensureDskInWorker(): Promise<boolean> {
  const worker = getCryptoWorker();
  if (await loadPersistedDskIntoWorker()) {
    return true;
  }

  try {
    await worker.generateDsk();
    return true;
  } catch {
    return false;
  }
}

export async function persistCurrentDeviceKeys(userId: string): Promise<boolean> {
  try {
    await getCryptoWorker().persistCurrentKeysWithDsk(userId, { persistUmk: false });
    return true;
  } catch {
    return false;
  }
}
