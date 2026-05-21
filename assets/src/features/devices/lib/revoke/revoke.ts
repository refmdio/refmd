import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError, devicesApi, encryptionApi } from "@/shared/api";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildDeviceRevocationKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/membership-events";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { performKekRotation } from "../kek-rotation/kek-rotation";

type DeviceRevocationReason = "security" | "retire";

type DeviceRevocationErrorCode = "retire_blocked_by_unbound_sessions";

export class DeviceRevocationError extends Error {
  readonly code: DeviceRevocationErrorCode;

  constructor(code: DeviceRevocationErrorCode, message: string) {
    super(message);
    this.name = "DeviceRevocationError";
    this.code = code;
  }
}

export function isRetireBlockedByUnboundSessionsError(
  error: unknown,
): error is DeviceRevocationError {
  return (
    error instanceof DeviceRevocationError && error.code === "retire_blocked_by_unbound_sessions"
  );
}

interface RevokeDeviceOutcome {
  warning: string | null;
}

function mapDeviceRevocationError(error: unknown): unknown {
  if (
    error instanceof ApiError &&
    error.status === 409 &&
    error.code === "retire_blocked_by_unbound_sessions"
  ) {
    return new DeviceRevocationError(
      "retire_blocked_by_unbound_sessions",
      "Safe device removal is blocked while an unbound session is still active.",
    );
  }

  return error;
}

function formatKekRotationWarning(error: unknown): string {
  const message = error instanceof Error ? error.message : "unknown error";
  return `Device removal key rotation failed: ${message}.`;
}

export async function revokeDevice(
  deviceId: string,
  reason: DeviceRevocationReason,
): Promise<RevokeDeviceOutcome> {
  const authSnapshot = authState();
  const deviceSnapshot = deviceState();
  if (!cryptoWorkerReady() || !authSnapshot || !deviceSnapshot?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  const revokedAtMs = Date.now();
  const worker = getCryptoWorker();
  const { signature } = await worker.createDeviceRevocationSignature({
    revokedDeviceId: deviceId,
    revocationMode: reason,
    revokedAtMs,
  });
  const devices = await devicesApi.list({ popDeviceId: deviceSnapshot.deviceId });
  const targetDevice = devices.devices.find((device) => device.id === deviceId);
  if (!targetDevice) throw new Error("device_revocation_target_not_found");
  const { workspace_ids: workspaceIds } = await encryptionApi.getWorkspaceIds();
  const userDirectory = await fetchVerifiedKeyDirectory({
    scopeKind: "user",
    scopeId: authSnapshot.user.id,
    popDeviceId: deviceSnapshot.deviceId,
  });
  const userAppend = await buildDeviceRevocationKeyDirectoryAppend({
    scopeKind: "user",
    scopeId: authSnapshot.user.id,
    userId: authSnapshot.user.id,
    checkpointEnvelope: userDirectory.checkpoint,
    revokedSigningKeyId: targetDevice.signing_key_id,
    revokedEncryptionKeyId: targetDevice.encryption_key_id,
    reason,
  });
  const workspaceAppends = await Promise.all(
    workspaceIds.map(async (workspaceId) => {
      const directory = await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        popDeviceId: deviceSnapshot.deviceId,
      });
      const append = await buildDeviceRevocationKeyDirectoryAppend({
        scopeKind: "workspace",
        scopeId: workspaceId,
        userId: authSnapshot.user.id,
        actorDeviceId: deviceSnapshot.deviceId,
        checkpointEnvelope: directory.checkpoint,
        revokedSigningKeyId: targetDevice.signing_key_id,
        revokedEncryptionKeyId: targetDevice.encryption_key_id,
        reason,
      });
      return {
        workspace_id: workspaceId,
        events: append.events,
        checkpoint: append.checkpoint,
        previousCheckpoint: directory.checkpoint,
      };
    }),
  );

  try {
    const result = await devicesApi.revoke(deviceId, reason, signature, revokedAtMs, {
      user_key_directory_events: userAppend.events,
      user_key_directory_checkpoint: userAppend.checkpoint,
      workspace_key_directory_appends: workspaceAppends.map(
        ({ workspace_id, events, checkpoint }) => ({
          workspace_id,
          events,
          checkpoint,
        }),
      ),
    });
    await advanceKeyDirectoryPinWithProof({
      scopeKind: "user",
      scopeId: authSnapshot.user.id,
      checkpointEnvelope: userAppend.checkpoint,
      checkpointAncestry: [userDirectory.checkpoint],
      eventAncestry: userAppend.events,
    });
    for (const append of workspaceAppends) {
      await advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: append.workspace_id,
        checkpointEnvelope: append.checkpoint,
        checkpointAncestry: [append.previousCheckpoint],
        eventAncestry: append.events,
      });
    }
    if (reason !== "security" || result.workspaces_needing_kek_rotation.length === 0) {
      return { warning: null };
    }

    await performKekRotation(
      result.workspaces_needing_kek_rotation,
      authSnapshot.user.id,
      deviceSnapshot.deviceId,
    ).catch((rotationError: unknown) => {
      throw new Error(formatKekRotationWarning(rotationError));
    });
    return { warning: null };
  } catch (error) {
    throw mapDeviceRevocationError(error);
  }
}
