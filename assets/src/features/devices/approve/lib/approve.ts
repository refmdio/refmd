import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { devicesApi, encryptionApi, trustTransferApi } from "@/shared/api";
import type { DeviceRegistrationInfo } from "@/shared/api/devices";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { persistWorkspaceKekForDevice } from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { joinUserDeviceEvents } from "@/features/devices/lib/device-events-channel";
interface PendingDeviceApprovalKeys {
  clientNonce: Uint8Array;
  deviceSigningPublic: Uint8Array;
  deviceEcdhPublic: Uint8Array;
}
type DeviceApprovalStep = "verify" | "distributing";
export function decodePendingDeviceApprovalKeys(
  device: DeviceRegistrationInfo,
): PendingDeviceApprovalKeys {
  return {
    clientNonce: base64UrlDecode(device.client_nonce),
    deviceSigningPublic: base64UrlDecode(device.signing_public_key),
    deviceEcdhPublic: base64UrlDecode(device.ecdh_public_key),
  };
}
export async function checkPendingDeviceApprovalTofu(
  device: DeviceRegistrationInfo,
): Promise<string | null> {
  const auth = authState();
  if (!auth) {
    return null;
  }
  const worker = getCryptoWorker();
  const decoded = decodePendingDeviceApprovalKeys(device);
  const result = await worker.tofuVerify({
    userId: auth.user.id,
    deviceId: device.id,
    signingPublicKey: decoded.deviceSigningPublic,
    ecdhPublicKey: decoded.deviceEcdhPublic,
  });
  if (result.status === "identity_key_changed") {
    return "Identity key changed for this device. This may indicate tampering.";
  }
  if (result.status === "ecdh_key_mismatch") {
    return "ECDH key mismatch for this device. This may indicate tampering.";
  }
  return null;
}
export async function approveDeviceRegistration(params: {
  device: DeviceRegistrationInfo;
  transferNonce: string | null;
  onStepChange?: (step: DeviceApprovalStep) => void;
}): Promise<void> {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("Identity keys or device not available");
  }
  if (!auth.identitySigningPublic) {
    throw new Error("Identity signing public key not available");
  }
  const worker = getCryptoWorker();
  const decoded = decodePendingDeviceApprovalKeys(params.device);
  const { signature } = await worker.signDeviceApproval({
    deviceId: params.device.id,
    deviceSigningPublic: decoded.deviceSigningPublic,
    deviceEcdhPublic: decoded.deviceEcdhPublic,
    clientNonce: decoded.clientNonce,
  });
  const approveResult = await devicesApi.approve(params.device.id, {
    identity_signature: base64UrlEncode(signature),
  });
  const approvedDevice = await verifyApprovedDeviceFromServer({
    approvedDeviceId: approveResult.device.id,
    originalDevice: params.device,
    identitySigningPublic: auth.identitySigningPublic,
    userId: auth.user.id,
  });
  params.onStepChange?.("distributing");
  try {
    await transferTrustState(approvedDevice.id, approvedDevice.ecdhPublicKey, params.transferNonce);
  } catch {
    // Trust state transfer is best effort.
  }
  try {
    await distributeKeks(
      currentDevice.deviceId,
      approvedDevice.id,
      approvedDevice.ecdhPublicKey,
      auth.user.id,
    );
  } catch {
    // KEK distribution is best effort.
  }
  const encryptedUmk = await worker.ecdhEncryptUmkForDevice({
    theirPublic: approvedDevice.ecdhPublicKey,
    senderDeviceId: currentDevice.deviceId,
    targetDeviceId: approvedDevice.id,
  });
  await devicesApi.distributeUmk(
    approvedDevice.id,
    currentDevice.deviceId,
    base64UrlEncode(encryptedUmk.ciphertext),
    base64UrlEncode(encryptedUmk.nonce),
  );
}
export async function rejectDeviceRegistration(deviceId: string): Promise<void> {
  try {
    await devicesApi.rejectRegistration(deviceId);
  } catch {
    // Already deleted or expired.
  }
}
async function distributeKeks(
  senderDeviceId: string,
  targetDeviceId: string,
  targetEcdhPublic: Uint8Array,
  userId: string,
): Promise<void> {
  const worker = getCryptoWorker();
  const { workspace_ids } = await encryptionApi.getWorkspaceIds();
  for (const workspaceId of workspace_ids) {
    try {
      const { keys, current_kek_version } = await encryptionApi.getWorkspaceKeysWithPop(
        workspaceId,
        senderDeviceId,
      );
      if (keys.length === 0 || current_kek_version === 0) {
        continue;
      }
      const activeKey = keys.find((key) => key.key_version === current_kek_version);
      if (!activeKey?.sender_ecdh_public_key || !activeKey.sender_signing_public_key) {
        continue;
      }
      const senderSigningPublic = base64UrlDecode(activeKey.sender_signing_public_key);
      const senderEcdhPublic = base64UrlDecode(activeKey.sender_ecdh_public_key);
      const tofuResult = await worker.tofuVerify({
        userId,
        deviceId: activeKey.sender_device_id,
        signingPublicKey: senderSigningPublic,
        ecdhPublicKey: senderEcdhPublic,
      });
      if (
        tofuResult.status === "identity_key_changed" ||
        tofuResult.status === "ecdh_key_mismatch"
      ) {
        throw new Error("Key verification failed for KEK sender device. Aborting distribution.");
      }
      if (tofuResult.status === "first_seen") {
        await worker.tofuTrustDevice({
          userId,
          deviceId: activeKey.sender_device_id,
          signingPublicKey: senderSigningPublic,
          ecdhPublicKey: senderEcdhPublic,
        });
      } else if (tofuResult.status === "known_trusted") {
        await worker.tofuUpdateLastSeen({
          userId,
          deviceId: activeKey.sender_device_id,
        });
      }
      await worker.decryptKekFromDeviceEnvelope({
        encryptedKek: base64UrlDecode(activeKey.encrypted_kek),
        nonce: base64UrlDecode(activeKey.nonce),
        senderEcdhPublic,
        workspaceId,
        userId,
        senderDeviceId: activeKey.sender_device_id,
        targetDeviceId: senderDeviceId,
        keyVersion: activeKey.key_version,
      });
      await persistWorkspaceKekForDevice({
        workspaceId,
        userId,
        senderDeviceId,
        targetDeviceId,
        targetDeviceEcdhPublic: targetEcdhPublic,
        keyVersion: activeKey.key_version,
        isActive: true,
      });
    } catch {
      // Per-workspace KEK distribution is best effort.
    }
  }
}
async function transferTrustState(
  targetDeviceId: string,
  targetDeviceEcdhPublic: Uint8Array,
  preReceivedNonce: string | null,
): Promise<void> {
  const nonceBase64 = preReceivedNonce ?? (await waitForTrustTransferNonce(targetDeviceId));
  if (!nonceBase64) {
    return;
  }
  const worker = getCryptoWorker();
  const encryptedState = await worker.encryptTrustState({
    targetDeviceId,
    targetDeviceEcdhPublic,
    transferNonce: base64UrlDecode(nonceBase64),
  });
  if ("empty" in encryptedState) {
    return;
  }
  await trustTransferApi.submitState({
    target_device_id: targetDeviceId,
    transfer_nonce: nonceBase64,
    ciphertext: base64UrlEncode(encryptedState.ciphertext),
    nonce: base64UrlEncode(encryptedState.nonce),
    signature: base64UrlEncode(encryptedState.signature),
  });
}
function waitForTrustTransferNonce(targetDeviceId: string): Promise<string | null> {
  return new Promise((resolve) => {
    let settled = false;
    let handle: { dispose: () => void } | undefined;

    const finish = (nonce: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      handle?.dispose();
      resolve(nonce);
    };

    const timeout = setTimeout(() => {
      finish(null);
    }, 10000);

    joinUserDeviceEvents({
      onTrustTransferNonceReady: (data) => {
        if (data.new_device_id === targetDeviceId && data.nonce) {
          finish(data.nonce);
        }
      },
      onError: () => finish(null),
      onClose: () => finish(null),
    })
      .then((joined) => {
        if (settled) {
          joined.dispose();
          return;
        }
        handle = joined;
      })
      .catch(() => finish(null));
  });
}
async function verifyApprovedDeviceFromServer(params: {
  approvedDeviceId: string;
  originalDevice: DeviceRegistrationInfo;
  identitySigningPublic: Uint8Array;
  userId: string;
}): Promise<{
  id: string;
  ecdhPublicKey: Uint8Array;
}> {
  const worker = getCryptoWorker();
  const { devices } = await devicesApi.list();
  const approvedDevice = devices.find((device) => device.id === params.approvedDeviceId);
  if (!approvedDevice) {
    throw new Error("Approved device not found on server");
  }
  if (
    approvedDevice.signing_public_key !== params.originalDevice.signing_public_key ||
    approvedDevice.ecdh_public_key !== params.originalDevice.ecdh_public_key
  ) {
    throw new Error(
      "Server returned different keys after approval. Possible key substitution. Aborting.",
    );
  }
  if (!approvedDevice.identity_signature || !approvedDevice.client_nonce) {
    throw new Error("Approved device missing identity signature. Aborting.");
  }
  const signingPublicKey = base64UrlDecode(approvedDevice.signing_public_key);
  const ecdhPublicKey = base64UrlDecode(approvedDevice.ecdh_public_key);
  const signatureValid = await worker.verifyDeviceIdentitySignature({
    deviceId: approvedDevice.id,
    deviceSigningPublic: signingPublicKey,
    deviceEcdhPublic: ecdhPublicKey,
    clientNonce: base64UrlDecode(approvedDevice.client_nonce),
    identitySignature: base64UrlDecode(approvedDevice.identity_signature),
    identitySigningPublic: params.identitySigningPublic,
  });
  if (!signatureValid) {
    throw new Error(
      "Identity signature verification failed. Possible server-side tampering. Aborting.",
    );
  }
  const tofuResult = await worker.tofuVerify({
    userId: params.userId,
    deviceId: approvedDevice.id,
    signingPublicKey,
    ecdhPublicKey,
  });
  if (tofuResult.status === "ecdh_key_mismatch" || tofuResult.status === "identity_key_changed") {
    throw new Error("Key verification failed before key distribution. Aborting.");
  }
  if (tofuResult.status === "first_seen") {
    await worker.tofuTrustDevice({
      userId: params.userId,
      deviceId: approvedDevice.id,
      signingPublicKey,
      ecdhPublicKey,
    });
  } else if (tofuResult.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({
      userId: params.userId,
      deviceId: approvedDevice.id,
    });
  }
  return {
    id: approvedDevice.id,
    ecdhPublicKey,
  };
}
