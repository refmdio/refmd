import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  getWorkspaceIds: vi.fn(),
  list: vi.fn(),
  revoke: vi.fn(),
  createDeviceRevocationSignature: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  buildDeviceRevocationKeyDirectoryAppend: vi.fn(),
  advanceKeyDirectoryPinWithProof: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  ApiError: class ApiError extends Error {},
  devicesApi: {
    list: mocks.list,
    revoke: mocks.revoke,
  },
  encryptionApi: {
    getWorkspaceIds: mocks.getWorkspaceIds,
  },
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/crypto/key-directory/membership-events", () => ({
  buildDeviceRevocationKeyDirectoryAppend: mocks.buildDeviceRevocationKeyDirectoryAppend,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advanceKeyDirectoryPinWithProof,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    createDeviceRevocationSignature: mocks.createDeviceRevocationSignature,
  }),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  cryptoWorkerReady: mocks.cryptoWorkerReady,
  deviceState: mocks.deviceState,
}));

import { revokeDevice } from "./revoke";

describe("revoke", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "user_1" } });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.deviceState.mockReturnValue({ deviceId: "device_current" });
    mocks.createDeviceRevocationSignature.mockResolvedValue({
      signature: {
        protocol: "refmd.hybrid-signature",
        version: 1,
        suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
        suite_rank: 1000,
        signing_key_id: "signing_key_current",
        transcript_hash: "hash",
        ed25519: "ed25519",
        mldsa65: "mldsa65",
      },
    });
    mocks.list.mockResolvedValue({
      devices: [
        {
          id: "device_target",
          signing_key_id: "signing_key_target",
          encryption_key_id: "encryption_key_target",
        },
      ],
    });
    mocks.getWorkspaceIds.mockResolvedValue({ workspace_ids: ["workspace_1"] });
    mocks.fetchVerifiedKeyDirectory.mockImplementation(({ scopeKind }: { scopeKind: string }) =>
      Promise.resolve({ checkpoint: { payload: { scope_kind: scopeKind } } }),
    );
    mocks.buildDeviceRevocationKeyDirectoryAppend.mockResolvedValue({
      events: [{ payload: { event_type: "signing_key_revoked" } }],
      checkpoint: { payload: { sequence: 2 } },
    });
    mocks.advanceKeyDirectoryPinWithProof.mockResolvedValue(undefined);
    mocks.revoke.mockResolvedValue({
      revoked_device_id: "device_target",
      revocation_mode: "retire",
      workspaces_needing_kek_rotation: [],
    });
  });

  it("signs and submits hybrid device revocation", async () => {
    const result = await revokeDevice("device_target", "retire");

    expect(result).toEqual({ warning: null });
    expect(mocks.createDeviceRevocationSignature).toHaveBeenCalledWith({
      revokedDeviceId: "device_target",
      revocationMode: "retire",
      revokedAtMs: expect.any(Number),
    });
    expect(mocks.revoke).toHaveBeenCalledWith(
      "device_target",
      "retire",
      {
        protocol: "refmd.hybrid-signature",
        version: 1,
        suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
        suite_rank: 1000,
        signing_key_id: "signing_key_current",
        transcript_hash: "hash",
        ed25519: "ed25519",
        mldsa65: "mldsa65",
      },
      expect.any(Number),
      {
        user_key_directory_events: [{ payload: { event_type: "signing_key_revoked" } }],
        user_key_directory_checkpoint: { payload: { sequence: 2 } },
        workspace_key_directory_appends: [
          {
            workspace_id: "workspace_1",
            events: [{ payload: { event_type: "signing_key_revoked" } }],
            checkpoint: { payload: { sequence: 2 } },
          },
        ],
      },
    );
    expect(mocks.advanceKeyDirectoryPinWithProof).toHaveBeenCalledTimes(2);
  });
});
