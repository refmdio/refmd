import { CryptoWorkerClient } from "./client";

const scopedWorkers = new Map<string, CryptoWorkerClient>();

export function getScopedCryptoWorker(scope: string): CryptoWorkerClient {
  let worker = scopedWorkers.get(scope);
  if (!worker) {
    worker = new CryptoWorkerClient();
    scopedWorkers.set(scope, worker);
  }
  return worker;
}

export function getShareParticipantCryptoWorker(shareSlug: string): CryptoWorkerClient {
  return getScopedCryptoWorker(`share:${shareSlug}`);
}

export function terminateScopedCryptoWorker(scope: string): void {
  const worker = scopedWorkers.get(scope);
  if (!worker) return;
  worker.terminate();
  scopedWorkers.delete(scope);
}

export function terminateAllScopedCryptoWorkers(): void {
  for (const worker of scopedWorkers.values()) {
    worker.terminate();
  }
  scopedWorkers.clear();
}
