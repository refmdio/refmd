import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError, workspacesApi, type components } from "@/shared/api";
import { createWorkspaceAuthorityAuthorization } from "@/shared/lib/crypto/workspace-authority-authorization";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

const KEY_DIRECTORY_APPEND_ATTEMPTS = 2;

export async function changeWorkspaceMemberRoleWithKeyDirectory(input: {
  workspaceId: string;
  targetUserId: string;
  previousRoleId: string;
  previousBaseRole: string;
  permissionVersion: number;
  roleId: string;
}): Promise<components["schemas"]["WorkspaceAuthorityMutationResponse"]> {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  let response: components["schemas"]["WorkspaceAuthorityMutationResponse"] | null = null;

  for (let attempt = 0; attempt < KEY_DIRECTORY_APPEND_ATTEMPTS; attempt += 1) {
    await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: input.workspaceId,
      rrpDeviceId: currentDevice.deviceId,
    });
    try {
      const intent = await workspacesApi.prepareMemberRoleChange(
        input.workspaceId,
        input.targetUserId,
        {
          role_id: input.roleId,
        },
      );
      const authorization = await createWorkspaceAuthorityAuthorization({
        worker: getCryptoWorker(),
        intent: intent as unknown as StrictJsonValue,
      });
      response = await workspacesApi.commitMemberRoleChange(
        input.workspaceId,
        input.targetUserId,
        authorization,
      );
      break;
    } catch (error) {
      if (!isInvalidKeyDirectoryError(error) || attempt === KEY_DIRECTORY_APPEND_ATTEMPTS - 1) {
        throw error;
      }
    }
  }

  if (!response) {
    throw new Error("workspace_member_role_change_response_missing");
  }
  await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    rrpDeviceId: currentDevice.deviceId,
  });
  return response;
}

function isInvalidKeyDirectoryError(error: unknown): boolean {
  return error instanceof ApiError && error.code === "invalid_key_directory";
}
