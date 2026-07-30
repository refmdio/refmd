import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError, devicesApi, securityCheckpointsApi } from "@/shared/api";
import { verifyAndPinAuditCheckpoint } from "@/shared/lib/anti-rollback/audit-checkpoint-pin";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  createDeviceRevocationAuthorization,
  materializeDeviceRevocationKeyDirectory,
} from "@/shared/lib/crypto/device-revocation-authorization";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import type { components } from "@/shared/api/schema";

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

export async function revokeDevice(
  deviceId: string,
  reason: DeviceRevocationReason,
): Promise<RevokeDeviceOutcome> {
  const auth = authState();
  const device = deviceState();
  if (!cryptoWorkerReady() || !auth?.user || !device?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  const command: components["schemas"]["DeviceRevocationCommand"] = {
    device_id: deviceId,
    revocation_mode: reason,
  };

  try {
    const intent = (await devicesApi.revocationIntent(
      deviceId,
      command,
    )) as unknown as StrictJsonValue;
    const currentDirectory = await fetchVerifiedKeyDirectory({
      scopeKind: "user",
      scopeId: auth.user.id,
      rrpDeviceId: device.deviceId,
    });
    const authorization = await createDeviceRevocationAuthorization({
      worker: getCryptoWorker(),
      intent,
    });
    const result = await devicesApi.revoke(
      deviceId,
      authorization as unknown as components["schemas"]["DeviceRevocationAuthorization"],
    );
    const directory = materializeDeviceRevocationKeyDirectory(intent, authorization);
    await advanceKeyDirectoryPinWithProof({
      scopeKind: "user",
      scopeId: auth.user.id,
      checkpointEnvelope: directory.checkpoint,
      checkpointAncestry: [currentDirectory.checkpoint],
      eventAncestry: directory.events,
    });
    const checkpoints = await securityCheckpointsApi.current();
    await verifyAndPinAuditCheckpoint(checkpoints.user_audit_checkpoint);
    if (result.revoked_device_id !== deviceId || result.revocation_mode !== reason) {
      throw new Error("device_revocation_response_mismatch");
    }
    return { warning: null };
  } catch (error) {
    throw mapDeviceRevocationError(error);
  }
}
