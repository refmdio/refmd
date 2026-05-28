import { authApi, encryptionApi } from "@/shared/api";
import { getKeyDirectoryPin } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
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
    issuedAtEventSequence: number;
    expiresEventSequence: number;
  }): Promise<InitialAkeResponderPrekeyRecord>;
}

export function resolveRegistrationInitialAkeIssuedAtEventSequence(input: {
  candidateUserEventHeadSequence?: number | null;
  pinnedEventHeadSequence?: number | null;
}): number {
  if (typeof input.candidateUserEventHeadSequence === "number") {
    return input.candidateUserEventHeadSequence;
  }

  return input.pinnedEventHeadSequence ?? 1;
}

export async function generateRegistrationInitialAkeResponderPrekeys(params: {
  userId: string;
  deviceId: string;
  workspaceIds: string[];
  issuedAtEventSequence: number;
  worker: InitialAkePrekeyWorker;
  operationIdFactory?: () => string;
}): Promise<RegistrationInitialAkeResponderPrekeys> {
  const expiresEventSequence = params.issuedAtEventSequence + 1;
  const nextOperationId = params.operationIdFactory ?? (() => crypto.randomUUID());
  const umkDistribution = await params.worker.generateInitialAkeResponderPrekey({
    operationId: params.deviceId,
    userId: params.userId,
    deviceId: params.deviceId,
    purpose: "umk_distribution",
    issuedAtEventSequence: params.issuedAtEventSequence,
    expiresEventSequence,
  });
  const trustTransfer = await params.worker.generateInitialAkeResponderPrekey({
    operationId: nextOperationId(),
    userId: params.userId,
    deviceId: params.deviceId,
    purpose: "trust_transfer",
    issuedAtEventSequence: params.issuedAtEventSequence,
    expiresEventSequence,
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
        issuedAtEventSequence: params.issuedAtEventSequence,
        expiresEventSequence,
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
}): Promise<RegistrationInitialAkeResponderPrekeys> {
  const me = await authApi.me();
  const { workspace_ids: workspaceIds } = await encryptionApi.getWorkspaceIds();
  const userKeyDirectoryPin = await getKeyDirectoryPin("user", params.userId);
  const issuedAtEventSequence = resolveRegistrationInitialAkeIssuedAtEventSequence({
    candidateUserEventHeadSequence: me.candidate_user_event_head_sequence,
    pinnedEventHeadSequence: userKeyDirectoryPin?.eventHeadSequence,
  });

  return generateRegistrationInitialAkeResponderPrekeys({
    userId: params.userId,
    deviceId: params.deviceId,
    workspaceIds,
    issuedAtEventSequence,
    worker: getCryptoWorker(),
  });
}
