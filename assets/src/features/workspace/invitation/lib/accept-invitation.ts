import { ApiError, encryptionApi, workspacesApi } from "@/shared/api";
import type { AuthState, DeviceState } from "@/entities/session";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import {
  persistWorkspaceKekBackup,
  persistWorkspaceKekForDevice,
  persistWorkspaceKekLocally,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
const KEK_SAVE_MAX_RETRIES = 3;
interface InvitationAcceptResult {
  encrypted_kek: string;
  kek_nonce: string;
  workspace_id: string;
  workspace_name: string;
  invitation_id: string;
  kek_version: number;
  role_name?: string | null;
}
interface KekSaveState {
  deviceSaved: boolean;
  umkSaved: boolean;
}
export interface AcceptedWorkspaceMembership {
  workspaceId: string;
  workspaceName: string;
  roleName: string | null;
}
type InvitationAcceptanceOutcome =
  | {
      status: "success";
      membership: AcceptedWorkspaceMembership | null;
    }
  | {
      status: "partial";
      membership: AcceptedWorkspaceMembership | null;
      warning: string;
    };
async function retryAsync<T>(fn: () => Promise<T>, retries: number): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}
async function decryptInvitationKek(
  acceptResult: InvitationAcceptResult,
  tokenBytes: Uint8Array,
): Promise<void> {
  const worker = getCryptoWorker();
  await worker.decryptKekFromInvitation({
    encryptedKek: base64UrlDecode(acceptResult.encrypted_kek),
    nonce: base64UrlDecode(acceptResult.kek_nonce),
    token: tokenBytes,
    workspaceId: acceptResult.workspace_id,
    invitationId: acceptResult.invitation_id,
    keyVersion: acceptResult.kek_version,
  });
}
async function recoverFromMemberEnvelope(
  workspaceId: string,
  auth: AuthState,
  device: Pick<DeviceState, "deviceId" | "deviceEcdhPublic">,
): Promise<void> {
  if (!auth.identityEcdhPublic) {
    throw new Error("Identity keys not available for KEK recovery.");
  }
  const worker = getCryptoWorker();
  const envelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
  if (!envelope || !envelope.sender_ecdh_public_key || !envelope.sender_signing_public_key) {
    throw new Error(
      "Encryption key recovery is not yet available. A workspace administrator needs to complete key rotation first.",
    );
  }
  const senderEcdhPk = base64UrlDecode(envelope.sender_ecdh_public_key);
  const senderSigningPk = base64UrlDecode(envelope.sender_signing_public_key);
  const tofuResult = await worker.tofuVerify({
    userId: envelope.sender_user_id,
    deviceId: envelope.sender_device_id,
    signingPublicKey: senderSigningPk,
    ecdhPublicKey: senderEcdhPk,
  });
  if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
    throw new Error("Key verification failed for member envelope sender.");
  }
  if (tofuResult.status === "first_seen") {
    await worker.tofuTrustDevice({
      userId: envelope.sender_user_id,
      deviceId: envelope.sender_device_id,
      signingPublicKey: senderSigningPk,
      ecdhPublicKey: senderEcdhPk,
    });
  } else if (tofuResult.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({
      userId: envelope.sender_user_id,
      deviceId: envelope.sender_device_id,
    });
  }
  await worker.decryptKekFromMemberEnvelope({
    encryptedKek: base64UrlDecode(envelope.encrypted_kek),
    nonce: base64UrlDecode(envelope.nonce),
    senderIdentityEcdhPublic: senderEcdhPk,
    workspaceId,
    targetUserId: auth.user.id,
    keyVersion: envelope.key_version,
    senderDeviceId: envelope.sender_device_id,
  });
  await persistWorkspaceKekLocally({
    workspaceId,
    userId: auth.user.id,
    deviceId: device.deviceId,
    deviceEcdhPublic: device.deviceEcdhPublic,
    keyVersion: envelope.key_version,
    ignoreConflict: true,
  });
}
async function persistKekCopies(
  acceptResult: Pick<InvitationAcceptResult, "workspace_id" | "kek_version">,
  auth: AuthState,
  device: DeviceState,
  saveState: KekSaveState,
): Promise<KekSaveState> {
  let { deviceSaved, umkSaved } = saveState;
  if (!deviceSaved) {
    if (!device.deviceEcdhPublic) {
      throw new Error("Device encryption key is not available.");
    }
    const targetDeviceEcdhPublic = device.deviceEcdhPublic;
    try {
      await retryAsync(
        () =>
          persistWorkspaceKekForDevice({
            workspaceId: acceptResult.workspace_id,
            userId: auth.user.id,
            senderDeviceId: device.deviceId,
            targetDeviceId: device.deviceId,
            targetDeviceEcdhPublic,
            keyVersion: acceptResult.kek_version,
            ignoreConflict: true,
          }),
        KEK_SAVE_MAX_RETRIES,
      );
      deviceSaved = true;
    } catch {
      // Retries exhausted for device envelope.
    }
  }
  if (!umkSaved) {
    try {
      await retryAsync(
        () =>
          persistWorkspaceKekBackup({
            workspaceId: acceptResult.workspace_id,
            userId: auth.user.id,
            keyVersion: acceptResult.kek_version,
            ignoreConflict: true,
          }),
        KEK_SAVE_MAX_RETRIES,
      );
      umkSaved = true;
    } catch {
      // Retries exhausted for UMK backup.
    }
  }
  return { deviceSaved, umkSaved };
}
export async function acceptInvitationWithKekPersistence({
  token,
  auth,
  device,
}: {
  token: string;
  auth: AuthState;
  device: DeviceState;
}): Promise<InvitationAcceptanceOutcome> {
  const tokenBytes = base64UrlDecode(token);
  const maxAcceptAttempts = 2;
  let savedWorkspaceId: string | null = null;
  let membership: AcceptedWorkspaceMembership | null = null;
  let lastAcceptResult: Pick<InvitationAcceptResult, "workspace_id" | "kek_version"> | null = null;
  let kekDecrypted = false;
  let saveState: KekSaveState = { deviceSaved: false, umkSaved: false };
  for (let attempt = 0; attempt < maxAcceptAttempts; attempt++) {
    let acceptResult: InvitationAcceptResult;
    try {
      acceptResult = await workspacesApi.acceptInvitation(token);
    } catch (error) {
      if (
        error instanceof ApiError &&
        error.status === 410 &&
        error.body.error === "invitation_kek_outdated"
      ) {
        const bodyWorkspaceId =
          typeof error.body.workspace_id === "string" ? error.body.workspace_id : null;
        const recoveryWorkspaceId = savedWorkspaceId || bodyWorkspaceId;
        if (recoveryWorkspaceId) {
          try {
            await recoverFromMemberEnvelope(recoveryWorkspaceId, auth, {
              deviceId: device.deviceId,
              deviceEcdhPublic: device.deviceEcdhPublic,
            });
            return { status: "success", membership };
          } catch {
            // Member envelope not available yet.
          }
        }
        throw new Error(
          "This invitation uses an outdated encryption key. Please request a new invitation from the workspace administrator.",
        );
      }
      if (
        error instanceof ApiError &&
        error.status === 409 &&
        error.body.error === "kek_rotation_in_progress"
      ) {
        return {
          status: "partial",
          membership,
          warning: savedWorkspaceId
            ? "A key rotation is currently in progress for this workspace. Please try again after the rotation is complete, or go to your dashboard where key distribution will happen automatically."
            : "A key rotation is currently in progress for this workspace. Please try again after the rotation is complete, or request a new invitation from the workspace administrator.",
        };
      }
      throw error;
    }
    savedWorkspaceId = acceptResult.workspace_id;
    membership ??= {
      workspaceId: acceptResult.workspace_id,
      workspaceName: acceptResult.workspace_name,
      roleName: acceptResult.role_name ?? null,
    };
    try {
      await decryptInvitationKek(acceptResult, tokenBytes);
      kekDecrypted = true;
    } catch {
      throw new Error("KEK decryption failed. Please request a new invitation link.");
    }
    lastAcceptResult = acceptResult;
    saveState = await persistKekCopies(acceptResult, auth, device, saveState);
    if (saveState.deviceSaved && saveState.umkSaved) {
      return { status: "success", membership };
    }
    if (saveState.deviceSaved || saveState.umkSaved) {
      break;
    }
  }
  if (kekDecrypted && lastAcceptResult && !(saveState.deviceSaved && saveState.umkSaved)) {
    saveState = await persistKekCopies(lastAcceptResult, auth, device, saveState);
    if (saveState.deviceSaved && saveState.umkSaved) {
      return { status: "success", membership };
    }
  }
  return {
    status: "partial",
    membership,
    warning:
      "You have joined the workspace, but encryption key setup is incomplete. You can retry now, or contact a workspace administrator to receive a new invitation.",
  };
}
