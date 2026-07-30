import { encryptionApi } from "@/shared/api";
import type { InitialAkeResponderPrekeyRecord } from "@/shared/lib/crypto/initial-ake";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export interface RegistrationInitialAkeResponderPrekeys {
  umk_distribution: InitialAkeResponderPrekeyRecord;
  trust_transfer: InitialAkeResponderPrekeyRecord;
  device_approval_kek_initial: Array<{
    workspace_id: string;
    prekey: InitialAkeResponderPrekeyRecord;
  }>;
}

interface InitialAkePrekeyWorker {
  generateInitialAkeResponderPrekey(params: {
    operationId: string;
    userId: string;
    deviceId: string;
    purpose: "umk_distribution" | "device_approval_kek_initial" | "trust_transfer";
    serverChallenge: string;
    issuedAtMs: number;
    expiresAtMs: number;
  }): Promise<InitialAkeResponderPrekeyRecord>;
}

export async function generateRegistrationInitialAkeResponderPrekeys(params: {
  userId: string;
  deviceId: string;
  workspaceIds: string[];
  serverChallenge: string;
  issuedAtMs: number;
  expiresAtMs: number;
  worker: InitialAkePrekeyWorker;
  operationIdFactory?: () => string;
}): Promise<RegistrationInitialAkeResponderPrekeys> {
  if (params.expiresAtMs !== params.issuedAtMs + 300_000) {
    throw new Error("responder_prekey_lifetime_invalid");
  }
  const nextOperationId = params.operationIdFactory ?? (() => crypto.randomUUID());
  const umkDistribution = await params.worker.generateInitialAkeResponderPrekey({
    operationId: nextOperationId(),
    userId: params.userId,
    deviceId: params.deviceId,
    purpose: "umk_distribution",
    serverChallenge: params.serverChallenge,
    issuedAtMs: params.issuedAtMs,
    expiresAtMs: params.expiresAtMs,
  });
  const trustTransfer = await params.worker.generateInitialAkeResponderPrekey({
    operationId: nextOperationId(),
    userId: params.userId,
    deviceId: params.deviceId,
    purpose: "trust_transfer",
    serverChallenge: params.serverChallenge,
    issuedAtMs: params.issuedAtMs,
    expiresAtMs: params.expiresAtMs,
  });
  const deviceApprovalKekInitial: RegistrationInitialAkeResponderPrekeys["device_approval_kek_initial"] =
    [];
  for (const workspaceId of params.workspaceIds) {
    deviceApprovalKekInitial.push({
      workspace_id: workspaceId,
      prekey: await params.worker.generateInitialAkeResponderPrekey({
        operationId: params.deviceId,
        userId: params.userId,
        deviceId: params.deviceId,
        purpose: "device_approval_kek_initial",
        serverChallenge: params.serverChallenge,
        issuedAtMs: params.issuedAtMs,
        expiresAtMs: params.expiresAtMs,
      }),
    });
  }

  return {
    umk_distribution: umkDistribution,
    trust_transfer: trustTransfer,
    device_approval_kek_initial: deviceApprovalKekInitial,
  };
}

export async function prepareRegistrationInitialAkeResponderPrekeys(params: {
  userId: string;
  deviceId: string;
  serverChallenge: string;
  issuedAtMs: number;
  expiresAtMs: number;
}): Promise<RegistrationInitialAkeResponderPrekeys> {
  const { workspace_ids: workspaceIds } = await encryptionApi.getWorkspaceIds();

  return generateRegistrationInitialAkeResponderPrekeys({
    userId: params.userId,
    deviceId: params.deviceId,
    workspaceIds,
    serverChallenge: params.serverChallenge,
    issuedAtMs: params.issuedAtMs,
    expiresAtMs: params.expiresAtMs,
    worker: getCryptoWorker(),
  });
}
