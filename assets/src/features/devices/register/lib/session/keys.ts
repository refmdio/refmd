import { persistWrappedDeviceKeys } from "@/shared/lib/auth/key-persistence";
import { loadDsk } from "@/shared/lib/crypto/dsk";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export async function loadPersistedDskIntoWorker(): Promise<boolean> {
  const worker = getCryptoWorker();

  const dsk = await loadDsk();
  if (!dsk) {
    return false;
  }

  await worker.setDsk(dsk);
  return true;
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
    const wrapped = await getCryptoWorker().wrapDeviceKeysWithDsk(userId);
    await persistWrappedDeviceKeys(wrapped);
    return true;
  } catch {
    return false;
  }
}
