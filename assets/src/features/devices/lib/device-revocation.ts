import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError, devicesApi } from "@/shared/api";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { performKekRotation } from "./kek-rotation";

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
  return `Device removed, but key rotation failed: ${message}. Keys will be rotated on next access.`;
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

  const worker = getCryptoWorker();
  const revokedAtMs = Date.now();

  const { signature } = await worker.signMessage({
    action: "device_revocation",
    payload: {
      device_id: deviceId,
      revocation_mode: reason,
      revoked_at: revokedAtMs,
      revoked_by_device_id: deviceSnapshot.deviceId,
      user_id: authSnapshot.user.id,
    },
  });

  try {
    const result = await devicesApi.revoke(
      deviceId,
      reason,
      base64UrlEncode(signature),
      revokedAtMs,
    );

    if (reason !== "security" || result.workspaces_needing_kek_rotation.length === 0) {
      return { warning: null };
    }

    try {
      await performKekRotation(
        result.workspaces_needing_kek_rotation,
        authSnapshot.user.id,
        deviceSnapshot.deviceId,
      );
      return { warning: null };
    } catch (rotationError) {
      return { warning: formatKekRotationWarning(rotationError) };
    }
  } catch (error) {
    throw mapDeviceRevocationError(error);
  }
}
