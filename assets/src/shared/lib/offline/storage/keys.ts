import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface OfflineDekEntry {
  documentId: string;
  keyVersion: number;
  cachedAt: number;
}

interface OfflineKekEntry {
  workspaceId: string;
  keyVersion: number;
  cachedAt: number;
}

export async function getOfflineDek(documentId: string): Promise<OfflineDekEntry | null> {
  return getCryptoWorker().loadOfflineDekMetadata(documentId);
}

export async function putOfflineDek(entry: OfflineDekEntry): Promise<void> {
  await getCryptoWorker().storeDekForOffline({
    documentId: entry.documentId,
    keyVersion: entry.keyVersion,
  });
}

export async function deleteOfflineDek(documentId: string): Promise<void> {
  await getCryptoWorker().deleteDekForOffline(documentId);
}

export async function getOfflineKek(workspaceId: string): Promise<OfflineKekEntry | null> {
  return getCryptoWorker().loadOfflineKekMetadata(workspaceId);
}

export async function putOfflineKek(entry: OfflineKekEntry): Promise<void> {
  await getCryptoWorker().storeKekForOffline({
    workspaceId: entry.workspaceId,
    keyVersion: entry.keyVersion,
  });
}

export async function deleteOfflineKek(workspaceId: string): Promise<void> {
  await getCryptoWorker().deleteKekForOffline(workspaceId);
}

export async function deleteOrphanedKeks(activeWorkspaceIds: Iterable<string>): Promise<void> {
  await getCryptoWorker().deleteOrphanedKeksForOffline(activeWorkspaceIds);
}
