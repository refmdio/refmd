import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  listRoles: vi.fn(),
  changeMemberRole: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  buildAppend: vi.fn(),
  advancePin: vi.fn(),
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
    listRoles: mocks.listRoles,
    changeMemberRole: mocks.changeMemberRole,
  },
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/crypto/key-directory/membership-events", () => ({
  buildWorkspaceMemberRoleChangesKeyDirectoryAppend: mocks.buildAppend,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advancePin,
}));

import { changeWorkspaceMemberRoleWithKeyDirectory } from "./change-role";

describe("changeWorkspaceMemberRoleWithKeyDirectory", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "owner" } });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.deviceState.mockReturnValue({ deviceId: "owner-device" });
    mocks.listRoles.mockResolvedValue({
      roles: [
        { id: "viewer", base_role: "viewer", permissions: [] },
        { id: "editor", base_role: "editor", permissions: [] },
      ],
    });
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({ checkpoint: { payload: {} } });
    mocks.buildAppend.mockResolvedValue({ events: [{}], checkpoint: { payload: {} } });
    mocks.changeMemberRole.mockResolvedValue({
      ok: true,
      workspaces_needing_kek_rotation: [],
    });
    mocks.advancePin.mockResolvedValue(undefined);
  });

  it("rebuilds once after a stale key-directory rejection", async () => {
    const ApiError = (await import("@/shared/api")).ApiError;
    mocks.changeMemberRole
      .mockRejectedValueOnce(new ApiError(422, { error: "invalid_key_directory" }))
      .mockResolvedValueOnce({ ok: true, workspaces_needing_kek_rotation: [] });

    await changeWorkspaceMemberRoleWithKeyDirectory({
      workspaceId: "workspace",
      targetUserId: "member",
      previousRoleId: "viewer",
      previousBaseRole: "viewer",
      permissionVersion: 1,
      roleId: "editor",
    });

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(2);
    expect(mocks.buildAppend).toHaveBeenCalledTimes(2);
    expect(mocks.changeMemberRole).toHaveBeenCalledTimes(2);
    expect(mocks.advancePin).toHaveBeenCalledTimes(1);
  });

  it("does not retry unrelated API failures", async () => {
    const ApiError = (await import("@/shared/api")).ApiError;
    mocks.changeMemberRole.mockRejectedValue(new ApiError(403, { error: "permission_denied" }));

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

    expect(mocks.changeMemberRole).toHaveBeenCalledTimes(1);
  });
});
