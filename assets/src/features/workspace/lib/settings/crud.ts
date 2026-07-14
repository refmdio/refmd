import { workspacesApi } from "@/shared/api";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import {
  persistWorkspaceKekForMember,
  persistWorkspaceKekLocally,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { buildInitialWorkspaceKeyDirectoryBootstrap } from "@/shared/lib/crypto/key-directory/initial";
import { pinInitialKeyDirectoryCheckpoint } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { verifyAndPinAuditCheckpoint } from "@/shared/lib/anti-rollback/audit-checkpoint-pin";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
type UpdateWorkspaceInput = Parameters<typeof workspacesApi.update>[1];
type UpdateWorkspaceFeaturesInput = Parameters<typeof workspacesApi.updateFeatures>[1];
interface CreateWorkspaceInput {
  name: string;
  description?: string;
  icon?: string;
}
export async function createWorkspaceWithInitialKek(
  data: CreateWorkspaceInput,
): Promise<string | null> {
  const auth = authState();
  const device = deviceState();
  if (!auth?.user || !device?.deviceId || !cryptoWorkerReady()) {
    return null;
  }
  const worker = getCryptoWorker();
  const publicKeys = await worker.getPublicKeys();
  if (
    !publicKeys.identityHybridSigningPublicKeyMaterial ||
    !publicKeys.identityHybridEncryptionPublicKeyMaterial ||
    !publicKeys.deviceHybridSigningPublicKeyMaterial ||
    !publicKeys.deviceHybridEncryptionPublicKeyMaterial
  ) {
    return null;
  }
  const workspaceId = crypto.randomUUID();
  const ownerRoleId = crypto.randomUUID();
  const initialDirectory = await buildInitialWorkspaceKeyDirectoryBootstrap({
    userId: auth.user.id,
    workspaceId,
    workspaceOwnerRoleId: ownerRoleId,
    deviceId: device.deviceId,
    identityHybridSigningPublicKeyMaterial: publicKeys.identityHybridSigningPublicKeyMaterial,
    identityHybridEncryptionPublicKeyMaterial: publicKeys.identityHybridEncryptionPublicKeyMaterial,
    deviceHybridSigningPublicKeyMaterial: publicKeys.deviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial: publicKeys.deviceHybridEncryptionPublicKeyMaterial,
  });
  const result = await workspacesApi.create({
    ...data,
    workspace_id: workspaceId,
    workspace_owner_role_id: ownerRoleId,
    workspace_key_directory_events: initialDirectory.workspaceEvents,
    workspace_key_directory_checkpoint: initialDirectory.workspaceCheckpoint,
  });
  if (!result.id) {
    return null;
  }
  await pinInitialKeyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: result.id,
    eventEnvelopes: initialDirectory.workspaceEvents,
    checkpointEnvelope: initialDirectory.workspaceCheckpoint,
  });
  await verifyAndPinAuditCheckpoint(result.audit_checkpoint);
  const { keyVersion } = await worker.generateKek(result.id);
  await persistWorkspaceKekLocally({
    workspaceId: result.id,
    userId: auth.user.id,
    deviceId: device.deviceId,
    deviceHybridEncryptionPublicKeyMaterial: publicKeys.deviceHybridEncryptionPublicKeyMaterial,
    keyVersion,
    isActive: true,
    keyDirectoryCheckpoint: initialDirectory.workspaceCheckpoint,
  });
  await persistWorkspaceKekForMember({
    workspaceId: result.id,
    userId: auth.user.id,
    senderDeviceId: device.deviceId,
    targetUserId: auth.user.id,
    targetIdentityHybridEncryptionPublicKeyMaterial:
      publicKeys.identityHybridEncryptionPublicKeyMaterial,
    keyVersion,
    rrpDeviceId: device.deviceId,
  });
  return result.id;
}
export async function getWorkspace(workspaceId: Parameters<typeof workspacesApi.get>[0]) {
  return workspacesApi.get(workspaceId);
}
export async function updateWorkspace(
  workspaceId: Parameters<typeof workspacesApi.update>[0],
  input: UpdateWorkspaceInput,
) {
  return workspacesApi.update(workspaceId, input);
}
export async function updateWorkspaceFeatures(
  workspaceId: Parameters<typeof workspacesApi.updateFeatures>[0],
  input: UpdateWorkspaceFeaturesInput,
) {
  return workspacesApi.updateFeatures(workspaceId, input);
}
export async function deleteWorkspace(workspaceId: Parameters<typeof workspacesApi.delete>[0]) {
  return workspacesApi.delete(workspaceId);
}
