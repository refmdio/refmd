import { devicesApi, encryptionApi } from "@/shared/api";
import type { WorkspaceRotationInfo } from "@/shared/api/devices";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import {
  persistWorkspaceKekBackup,
  persistWorkspaceKekForDevice,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

type TriggerKekRotationFn = (rotationList: WorkspaceRotationInfo[]) => Promise<void>;

export function createWorkspaceKekRotationTrigger(): TriggerKekRotationFn {
  return async (rotationList) => {
    if (rotationList.length === 0) return;

    const auth = authState();
    const device = deviceState();
    if (!cryptoWorkerReady() || !auth || !device?.deviceId) {
      throw new Error("KEK rotation prerequisites not met: crypto worker or device not ready");
    }

    await performKekRotation(rotationList, auth.user.id, device.deviceId);
  };
}

export async function performKekRotation(
  workspaces: WorkspaceRotationInfo[],
  userId: string,
  currentDeviceId: string,
): Promise<void> {
  const worker = getCryptoWorker();
  const activeDevices = await devicesApi.list();

  for (const device of activeDevices.devices) {
    const signingPk = base64UrlDecode(device.signing_public_key);
    const ecdhPk = base64UrlDecode(device.ecdh_public_key);
    const tofuResult = await worker.tofuVerify({
      userId,
      deviceId: device.id,
      signingPublicKey: signingPk,
      ecdhPublicKey: ecdhPk,
    });
    if (tofuResult.status === "ecdh_key_mismatch" || tofuResult.status === "identity_key_changed") {
      throw new Error("Device key verification failed. Aborting KEK rotation.");
    }

    if (!device.identity_signature || !device.client_nonce) {
      throw new Error(`Device ${device.name}: Missing identity signature. Aborting KEK rotation.`);
    }
    const sig = base64UrlDecode(device.identity_signature);
    const nonce = base64UrlDecode(device.client_nonce);
    const identitySigningPublic = authState()?.identitySigningPublic;
    if (!identitySigningPublic) {
      throw new Error("Identity signing public key not available. Aborting KEK rotation.");
    }
    const sigValid = await worker.verifyDeviceIdentitySignature({
      deviceId: device.id,
      deviceSigningPublic: signingPk,
      deviceEcdhPublic: ecdhPk,
      clientNonce: nonce,
      identitySignature: sig,
      identitySigningPublic,
    });
    if (!sigValid) {
      throw new Error(`Device ${device.name}: Invalid identity signature. Aborting KEK rotation.`);
    }

    if (tofuResult.status === "first_seen") {
      await worker.tofuTrustDevice({
        userId,
        deviceId: device.id,
        signingPublicKey: signingPk,
        ecdhPublicKey: ecdhPk,
      });
    } else if (tofuResult.status === "known_trusted") {
      await worker.tofuUpdateLastSeen({ userId, deviceId: device.id });
    }
  }

  const failedWorkspaces: string[] = [];

  for (const workspace of workspaces) {
    const workspaceId = workspace.workspace_id;
    try {
      const newVersion = workspace.current_kek_version + 1;

      await worker.generateKek(workspaceId, newVersion);

      for (const device of activeDevices.devices) {
        const targetEcdhPublic = base64UrlDecode(device.ecdh_public_key);
        await persistWorkspaceKekForDevice({
          workspaceId,
          userId,
          senderDeviceId: currentDeviceId,
          targetDeviceId: device.id,
          targetDeviceEcdhPublic: targetEcdhPublic,
          keyVersion: newVersion,
          isActive: true,
        });
      }

      const { members } = await encryptionApi.getWorkspaceMemberKeys(workspaceId);
      const envelopes = await Promise.all(
        members.map(async (member) => {
          const targetEcdhPublic = base64UrlDecode(member.ecdh_public_key);
          const envelope = await worker.encryptKekForMember({
            workspaceId,
            targetUserId: member.user_id,
            targetIdentityEcdhPublic: targetEcdhPublic,
            senderDeviceId: currentDeviceId,
            keyVersion: newVersion,
          });
          return {
            target_user_id: member.user_id,
            key_version: newVersion,
            sender_device_id: currentDeviceId,
            encrypted_kek: base64UrlEncode(envelope.encrypted),
            nonce: base64UrlEncode(envelope.nonce),
          };
        }),
      );

      await encryptionApi.saveMemberEnvelopes(workspaceId, envelopes);

      await persistWorkspaceKekBackup({
        workspaceId,
        userId,
        keyVersion: newVersion,
      });

      await encryptionApi.completeKekRotation(workspaceId, newVersion);
    } catch {
      failedWorkspaces.push(workspaceId);
    }
  }

  if (failedWorkspaces.length > 0) {
    throw new Error(
      `KEK rotation failed for ${failedWorkspaces.length} workspace(s). Keys will be rotated on next access.`,
    );
  }
}
