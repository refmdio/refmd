import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError, workspacesApi, type components } from "@/shared/api";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  createWorkspaceAuthorityAuthorization,
  materializeWorkspaceAuthorityKeyDirectory,
} from "@/shared/lib/crypto/workspace-authority-authorization";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

type RemoveMemberResponse = components["schemas"]["WorkspaceAuthorityMutationResponse"];
const KEY_DIRECTORY_APPEND_ATTEMPTS = 2;

export async function removeWorkspaceMemberWithKeyDirectory(
  workspaceId: string,
  targetUserId: string,
): Promise<RemoveMemberResponse> {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  let directory: Awaited<ReturnType<typeof fetchVerifiedKeyDirectory>> | null = null;
  let keyDirectoryAppend: ReturnType<typeof materializeWorkspaceAuthorityKeyDirectory> | null =
    null;
  let response: RemoveMemberResponse | null = null;

  for (let attempt = 0; attempt < KEY_DIRECTORY_APPEND_ATTEMPTS; attempt += 1) {
    directory = await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: workspaceId,
      rrpDeviceId: currentDevice.deviceId,
    });
    try {
      const intent = await workspacesApi.prepareMemberRemoval(workspaceId, targetUserId, {});
      const authorization = await createWorkspaceAuthorityAuthorization({
        worker: getCryptoWorker(),
        intent: intent as unknown as StrictJsonValue,
      });
      keyDirectoryAppend = materializeWorkspaceAuthorityKeyDirectory(
        intent as unknown as StrictJsonValue,
        authorization,
      );
      response = await workspacesApi.commitMemberRemoval(workspaceId, targetUserId, authorization);
      break;
    } catch (error) {
      if (!isInvalidKeyDirectoryError(error) || attempt === KEY_DIRECTORY_APPEND_ATTEMPTS - 1) {
        throw error;
      }
    }
  }

  if (!directory || !keyDirectoryAppend || !response) {
    throw new Error("workspace_member_removal_response_missing");
  }

  if (targetUserId === auth.user.id) {
    await advanceKeyDirectoryPinWithProof({
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointEnvelope: keyDirectoryAppend.checkpoint,
      checkpointAncestry: [directory.checkpoint],
      eventAncestry: keyDirectoryAppend.events,
    });
    return response as RemoveMemberResponse;
  }

  await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: workspaceId,
    rrpDeviceId: currentDevice.deviceId,
  });
  return response as RemoveMemberResponse;
}

function isInvalidKeyDirectoryError(error: unknown): boolean {
  return error instanceof ApiError && error.code === "invalid_key_directory";
}
