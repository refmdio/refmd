import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  prepareMemberRoleChange: vi.fn(),
  commitMemberRoleChange: vi.fn(),
  createAuthorization: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  cryptoWorkerReady: mocks.cryptoWorkerReady,
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/api", () => ({
  ApiError: class ApiError extends Error {
    code: string | null;

    constructor(_status: number, body: Record<string, unknown>) {
      super(String(body.error));
      this.code = typeof body.error === "string" ? body.error : null;
    }
  },
  workspacesApi: {
    prepareMemberRoleChange: mocks.prepareMemberRoleChange,
    commitMemberRoleChange: mocks.commitMemberRoleChange,
  },
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/crypto/workspace-authority-authorization", () => ({
  createWorkspaceAuthorityAuthorization: mocks.createAuthorization,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({}),
}));

import { changeWorkspaceMemberRoleWithKeyDirectory } from "./change-role";

describe("changeWorkspaceMemberRoleWithKeyDirectory", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "owner" } });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.deviceState.mockReturnValue({ deviceId: "owner-device" });
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({ checkpoint: { payload: {} } });
    mocks.prepareMemberRoleChange.mockResolvedValue({ protocol: "intent" });
    mocks.createAuthorization.mockResolvedValue({ protocol: "authorization" });
    mocks.commitMemberRoleChange.mockResolvedValue({
      status: "committed",
      event_type: "workspace.member.role_changed",
      workspace_id: "workspace",
      workspace_key_directory_checkpoint_hash: "hash",
      workspace_audit_checkpoint_hash: "hash",
      permission_loss: false,
    });
  });

  it("rebuilds once after a stale key-directory rejection", async () => {
    const ApiError = (await import("@/shared/api")).ApiError;
    mocks.commitMemberRoleChange
      .mockRejectedValueOnce(new ApiError(422, { error: "invalid_key_directory" }))
      .mockResolvedValueOnce({ status: "committed" });

    await changeWorkspaceMemberRoleWithKeyDirectory({
      workspaceId: "workspace",
      targetUserId: "member",
      previousRoleId: "viewer",
      previousBaseRole: "viewer",
      permissionVersion: 1,
      roleId: "editor",
    });

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(3);
    expect(mocks.prepareMemberRoleChange).toHaveBeenCalledTimes(2);
    expect(mocks.commitMemberRoleChange).toHaveBeenCalledTimes(2);
  });

  it("does not retry unrelated API failures", async () => {
    const ApiError = (await import("@/shared/api")).ApiError;
    mocks.commitMemberRoleChange.mockRejectedValue(
      new ApiError(403, { error: "permission_denied" }),
    );

    await expect(
      changeWorkspaceMemberRoleWithKeyDirectory({
        workspaceId: "workspace",
        targetUserId: "member",
        previousRoleId: "viewer",
        previousBaseRole: "viewer",
        permissionVersion: 1,
        roleId: "editor",
      }),
    ).rejects.toThrow("permission_denied");

    expect(mocks.commitMemberRoleChange).toHaveBeenCalledTimes(1);
  });
});
