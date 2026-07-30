import { type components, workspacesApi } from "@/shared/api";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { pinInitialKeyDirectoryCheckpoint } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { verifyAndPinAuditCheckpoint } from "@/shared/lib/anti-rollback/audit-checkpoint-pin";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  createWorkspaceGenesisAuthorization,
  materializeWorkspaceGenesisKeyDirectory,
} from "@/shared/lib/crypto/genesis-authorization";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
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
  await worker.generateKek(workspaceId, 1);
  const precommit = await worker.createGenesisWorkspaceMemberEnvelopePrecommit({
    workspaceId,
    userId: auth.user.id,
    deviceId: device.deviceId,
    recipientPublicKeyMaterial: publicKeys.identityHybridEncryptionPublicKeyMaterial,
  });
  const command = {
    protocol: "refmd.workspace-genesis-command" as const,
    version: 1 as const,
    name: data.name,
    description: data.description ?? null,
    icon: data.icon ?? null,
    workspace_id: workspaceId,
    owner_role_id: ownerRoleId,
    workspace_member_envelope_precommit: precommit,
  };
  const intent = (await workspacesApi.createIntent(
    command as unknown as components["schemas"]["WorkspaceGenesisCommand"],
  )) as unknown as StrictJsonValue;
  const authorization = await createWorkspaceGenesisAuthorization({ worker, intent, precommit });
  const result = await workspacesApi.create(
    authorization as unknown as components["schemas"]["WorkspaceGenesisAuthorization"],
  );
  if (!result.workspace_id || result.workspace_id !== workspaceId) {
    return null;
  }
  const initialDirectory = materializeWorkspaceGenesisKeyDirectory(intent, authorization);
  await pinInitialKeyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: result.workspace_id,
    eventEnvelopes: initialDirectory.workspaceEvents,
    checkpointEnvelope: initialDirectory.workspaceCheckpoint,
  });
  await verifyAndPinAuditCheckpoint(result.workspace_audit_checkpoint);
  return result.workspace_id;
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
