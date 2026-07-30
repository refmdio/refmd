import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  revocationIntent: vi.fn(),
  revoke: vi.fn(),
  currentCheckpoints: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  createAuthorization: vi.fn(),
  materialize: vi.fn(),
  advancePin: vi.fn(),
  verifyAudit: vi.fn(),
  worker: {},
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  cryptoWorkerReady: mocks.cryptoWorkerReady,
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    code: string | null;
    constructor(status: number, body: Record<string, unknown>) {
      super(`API error ${status}`);
      this.status = status;
      this.code = typeof body.error === "string" ? body.error : null;
    }
  },
  devicesApi: {
    revocationIntent: mocks.revocationIntent,
    revoke: mocks.revoke,
  },
  securityCheckpointsApi: { current: mocks.currentCheckpoints },
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/crypto/device-revocation-authorization", () => ({
  createDeviceRevocationAuthorization: mocks.createAuthorization,
  materializeDeviceRevocationKeyDirectory: mocks.materialize,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advancePin,
}));

vi.mock("@/shared/lib/anti-rollback/audit-checkpoint-pin", () => ({
  verifyAndPinAuditCheckpoint: mocks.verifyAudit,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => mocks.worker,
}));

import { ApiError } from "@/shared/api";
import { isRetireBlockedByUnboundSessionsError, revokeDevice } from "./revoke";

describe("revokeDevice", () => {
  const intent = { protocol: "refmd.audit.compound-append-intent" };
  const authorization = { protocol: "refmd.audit.compound-append-authorization" };
  const previousCheckpoint = { payload: { sequence: 2 } };
  const nextCheckpoint = { payload: { sequence: 3 } };
  const events = [{ payload: { event_type: "signing_key_revoked" } }];
  const userAuditCheckpoint = { signed_checkpoint: {} };

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "user_1" } });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.deviceState.mockReturnValue({ deviceId: "device_current" });
    mocks.revocationIntent.mockResolvedValue(intent);
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({ checkpoint: previousCheckpoint });
    mocks.createAuthorization.mockResolvedValue(authorization);
    mocks.materialize.mockReturnValue({ events, checkpoint: nextCheckpoint });
    mocks.revoke.mockResolvedValue({
      status: "committed",
      revoked_device_id: "device_target",
      revocation_mode: "retire",
      user_key_directory_checkpoint_hash: "checkpoint_hash",
      user_audit_checkpoint_hash: "audit_hash",
      workspaces_needing_kek_rotation: [],
    });
    mocks.currentCheckpoints.mockResolvedValue({
      user_audit_checkpoint: userAuditCheckpoint,
      workspace_audit_checkpoints: [],
    });
  });

  it("prepares, signs, commits, then advances key-directory and audit pins", async () => {
    await expect(revokeDevice("device_target", "retire")).resolves.toEqual({ warning: null });

    expect(mocks.revocationIntent).toHaveBeenCalledWith("device_target", {
      device_id: "device_target",
      revocation_mode: "retire",
    });
    expect(mocks.createAuthorization).toHaveBeenCalledWith({ worker: mocks.worker, intent });
    expect(mocks.revoke).toHaveBeenCalledWith("device_target", authorization);
    expect(mocks.advancePin).toHaveBeenCalledWith({
      scopeKind: "user",
      scopeId: "user_1",
      checkpointEnvelope: nextCheckpoint,
      checkpointAncestry: [previousCheckpoint],
      eventAncestry: events,
    });
    expect(mocks.verifyAudit).toHaveBeenCalledWith(userAuditCheckpoint);
    expect(mocks.revoke.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.advancePin.mock.invocationCallOrder[0]!,
    );
  });

  it("maps retire precondition conflicts", async () => {
    mocks.revocationIntent.mockRejectedValue(
      new ApiError(409, { error: "retire_blocked_by_unbound_sessions" }),
    );

    await expect(revokeDevice("device_target", "retire")).rejects.toSatisfy(
      isRetireBlockedByUnboundSessionsError,
    );
    expect(mocks.revoke).not.toHaveBeenCalled();
  });

  it("fails before network access when cryptographic state is unavailable", async () => {
    mocks.cryptoWorkerReady.mockReturnValue(false);
    await expect(revokeDevice("device_target", "retire")).rejects.toThrow(
      "Identity keys or device not available",
    );
    expect(mocks.revocationIntent).not.toHaveBeenCalled();
  });

  it("rejects a commit response for another device", async () => {
    mocks.revoke.mockResolvedValue({
      revoked_device_id: "device_other",
      revocation_mode: "retire",
    });
    await expect(revokeDevice("device_target", "retire")).rejects.toThrow(
      "device_revocation_response_mismatch",
    );
  });
});
