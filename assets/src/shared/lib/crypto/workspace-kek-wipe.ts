import { encryptionApi } from "@/shared/api/encryption";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import {
  deleteDocumentOfflineData,
  deleteOfflineCreated,
  deleteOfflineKek,
  getAllOfflineCreated,
  getAllOfflineDocumentMetas,
  getDocumentCache,
  getOfflineDocumentIndex,
  getPendingChanges,
} from "@/shared/lib/offline/storage/store";
import { getCryptoWorker } from "./worker/client";
import { buildCurrentDeviceKeyDeletionProof } from "./device-key-deletion-proof";

const pendingWorkspaceWipes = new Map<string, Promise<void>>();

export async function acknowledgeWorkspaceWipeIfRequired(params: {
  workspaceId: string;
  userId: string;
  deviceId: string;
}): Promise<void> {
  const existing = pendingWorkspaceWipes.get(params.workspaceId);
  if (existing) return existing;
  const acknowledgement = doAcknowledgeWorkspaceWipeIfRequired(params);
  pendingWorkspaceWipes.set(params.workspaceId, acknowledgement);
  try {
    await acknowledgement;
  } finally {
    if (pendingWorkspaceWipes.get(params.workspaceId) === acknowledgement) {
      pendingWorkspaceWipes.delete(params.workspaceId);
    }
  }
}

async function doAcknowledgeWorkspaceWipeIfRequired(params: {
  workspaceId: string;
  userId: string;
  deviceId: string;
}): Promise<void> {
  for (;;) {
    const requirement = await encryptionApi.getWorkspaceWipeRequirement(params.workspaceId);
    if (!requirement) return;
    if (requirement.workspace_id !== params.workspaceId) {
      throw new Error("workspace_wipe_scope_mismatch");
    }

    const directory = await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: params.workspaceId,
      rrpDeviceId: params.deviceId,
    });
    const documentVersions = await workspaceDocumentVersions(params.workspaceId);
    const worker = getCryptoWorker();
    for (const [documentId, versions] of documentVersions) {
      for (const version of versions) await worker.evictDek(documentId, version);
      await deleteDocumentOfflineData(documentId);
    }
    for (const entry of await getAllOfflineCreated()) {
      if (entry.workspaceId === params.workspaceId) await deleteOfflineCreated(entry.documentId);
    }
    await worker.setActiveKekVersion(params.workspaceId, requirement.required_kek_version);
    await worker.deleteKekVersion(params.workspaceId, requirement.old_key_version);
    await deleteOfflineKek(params.workspaceId);

    const proof = await buildCurrentDeviceKeyDeletionProof({
      workspaceId: params.workspaceId,
      userId: params.userId,
      deviceId: params.deviceId,
      rotationKind: "kek",
      scopeKind: "workspace",
      scopeId: params.workspaceId,
      oldKeyVersion: requirement.old_key_version,
      rotationCompletedEventHash: requirement.rotation_completed_event_hash,
      deletedSecretIdsHash: requirement.deleted_secret_ids_hash,
      checkpointEnvelope: directory.checkpoint,
    });
    await encryptionApi.acknowledgeWorkspaceWipe(params.workspaceId, {
      device_key_deletion_proof: proof as never,
    });
  }
}

async function workspaceDocumentVersions(workspaceId: string): Promise<Map<string, Set<number>>> {
  const [metas, index] = await Promise.all([
    getAllOfflineDocumentMetas(),
    getOfflineDocumentIndex(workspaceId),
  ]);
  const documentIds = new Set([
    ...metas.filter((entry) => entry.workspaceId === workspaceId).map((entry) => entry.documentId),
    ...index.map((entry) => entry.documentId),
  ]);
  const result = new Map<string, Set<number>>();
  await Promise.all(
    [...documentIds].map(async (documentId) => {
      const [cache, pending] = await Promise.all([
        getDocumentCache(documentId),
        getPendingChanges(documentId),
      ]);
      result.set(
        documentId,
        new Set(
          [cache?.keyVersion, pending?.keyVersion].filter(
            (version): version is number => typeof version === "number" && version > 0,
          ),
        ),
      );
    }),
  );
  return result;
}
