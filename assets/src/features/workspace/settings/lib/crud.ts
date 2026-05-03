import { workspacesApi } from "@/shared/api";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { persistWorkspaceKekLocally } from "@/shared/lib/crypto/workspace-kek-persistence";
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
  const result = await workspacesApi.create(data);
  if (!result.id) {
    return null;
  }
  const worker = getCryptoWorker();
  const { keyVersion } = await worker.generateKek(result.id);
  await persistWorkspaceKekLocally({
    workspaceId: result.id,
    userId: auth.user.id,
    deviceId: device.deviceId,
    deviceEcdhPublic: device.deviceEcdhPublic,
    keyVersion,
    isActive: true,
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
export async function removeWorkspaceMember(
  workspaceId: Parameters<typeof workspacesApi.removeMember>[0],
  userId: Parameters<typeof workspacesApi.removeMember>[1],
) {
  return workspacesApi.removeMember(workspaceId, userId);
}
