import type { CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";

type GuestWorkspaceKekWorker = Pick<
  CryptoWorkerClient,
  "storeKekForOffline" | "persistCurrentKeysWithDsk"
>;

interface PersistGuestWorkspaceKekParams {
  userId: string;
  workspaceId: string;
  keyVersion: number;
}

export async function persistRedeemedGuestWorkspaceKek(
  worker: GuestWorkspaceKekWorker,
  params: PersistGuestWorkspaceKekParams,
): Promise<void> {
  await worker.storeKekForOffline({
    workspaceId: params.workspaceId,
    keyVersion: params.keyVersion,
  });
  await worker.persistCurrentKeysWithDsk(params.userId);
}
