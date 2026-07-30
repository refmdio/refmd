import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  prepareMemberRemoval: vi.fn(),
  commitMemberRemoval: vi.fn(),
  createAuthorization: vi.fn(),
  materializeKeyDirectory: vi.fn(),
  advanceKeyDirectoryPinWithProof: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  cryptoWorkerReady: mocks.cryptoWorkerReady,
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    body: Record<string, unknown>;
    code: string | null;

    constructor(status: number, body: Record<string, unknown>) {
      super(`API error ${status}: ${JSON.stringify(body)}`);
      this.name = "ApiError";
      this.status = status;
      this.body = body;
      this.code = typeof body.error === "string" ? body.error : null;
    }
  },
  workspacesApi: {
    prepareMemberRemoval: mocks.prepareMemberRemoval,
    commitMemberRemoval: mocks.commitMemberRemoval,
  },
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advanceKeyDirectoryPinWithProof,
}));

vi.mock("@/shared/lib/crypto/workspace-authority-authorization", () => ({
  createWorkspaceAuthorityAuthorization: mocks.createAuthorization,
  materializeWorkspaceAuthorityKeyDirectory: mocks.materializeKeyDirectory,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({}),
}));

import { removeWorkspaceMemberWithKeyDirectory } from "./remove-member";

describe("removeWorkspaceMemberWithKeyDirectory", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "user-self" } });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.deviceState.mockReturnValue({ deviceId: "device-self" });
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({
      checkpoint: { payload: { sequence: 1 } },
    });
    mocks.materializeKeyDirectory.mockReturnValue({
      events: [{ payload: { event_type: "member_removed" } }],
      checkpoint: { payload: { sequence: 2 } },
    });
    mocks.prepareMemberRemoval.mockResolvedValue({ protocol: "intent" });
    mocks.createAuthorization.mockResolvedValue({ protocol: "authorization" });
    mocks.commitMemberRemoval.mockResolvedValue({
      status: "committed",
      event_type: "workspace.member.removed",
      workspace_id: "workspace-1",
      workspace_key_directory_checkpoint_hash: "hash",
      workspace_audit_checkpoint_hash: "hash",
      permission_loss: false,
    });
    mocks.advanceKeyDirectoryPinWithProof.mockResolvedValue(undefined);
  });

  it("requires canonical local pin advancement before self-leave completes", async () => {
    mocks.advanceKeyDirectoryPinWithProof.mockRejectedValue(new Error("pin advance failed"));

    await expect(removeWorkspaceMemberWithKeyDirectory("workspace-1", "user-self")).rejects.toThrow(
      "pin advance failed",
    );
    expect(mocks.advanceKeyDirectoryPinWithProof).toHaveBeenCalledTimes(1);
  });

  it("requires local workspace pin advancement when removing another member", async () => {
    mocks.fetchVerifiedKeyDirectory
      .mockResolvedValueOnce({ checkpoint: { payload: { sequence: 1 } } })
      .mockRejectedValueOnce(new Error("pin advance failed"));

    await expect(
      removeWorkspaceMemberWithKeyDirectory("workspace-1", "user-other"),
    ).rejects.toThrow("pin advance failed");
  });

  it("rebuilds the member-removal append once when the server rejects a stale key directory", async () => {
    const staleDirectory = { checkpoint: { payload: { sequence: 1 } } };
    const freshDirectory = { checkpoint: { payload: { sequence: 2 } } };
    const InvalidKeyDirectory = (await import("@/shared/api")).ApiError;
    mocks.fetchVerifiedKeyDirectory
      .mockResolvedValueOnce(staleDirectory)
      .mockResolvedValueOnce(freshDirectory);
    mocks.commitMemberRemoval
      .mockRejectedValueOnce(new InvalidKeyDirectory(422, { error: "invalid_key_directory" }))
      .mockResolvedValueOnce({ status: "committed" });

    await expect(
      removeWorkspaceMemberWithKeyDirectory("workspace-1", "user-self"),
    ).resolves.toEqual({
      status: "committed",
    });

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(2);
    expect(mocks.prepareMemberRemoval).toHaveBeenNthCalledWith(1, "workspace-1", "user-self", {});
    expect(mocks.prepareMemberRemoval).toHaveBeenNthCalledWith(2, "workspace-1", "user-self", {});
  });

  it("does not retry non-key-directory member removal errors", async () => {
    const ApiError = (await import("@/shared/api")).ApiError;
    mocks.commitMemberRemoval.mockRejectedValue(new ApiError(403, { error: "permission_denied" }));

    await expect(
      removeWorkspaceMemberWithKeyDirectory("workspace-1", "user-other"),
    ).rejects.toThrow("permission_denied");

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(1);
    expect(mocks.commitMemberRemoval).toHaveBeenCalledTimes(1);
  });
});
