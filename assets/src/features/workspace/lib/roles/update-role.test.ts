import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  listRoles: vi.fn(),
  listMembers: vi.fn(),
  updateRole: vi.fn(),
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
    listMembers: mocks.listMembers,
    updateRole: mocks.updateRole,
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

import { updateWorkspaceRoleWithKeyDirectory } from "./update-role";

describe("updateWorkspaceRoleWithKeyDirectory", () => {
  const role = {
    id: "editor",
    workspace_id: "workspace",
    name: "Editor",
    base_role: "editor" as const,
    is_default: false,
    created_at: "2026-07-15T00:00:00Z",
    permissions: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "owner" } });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.deviceState.mockReturnValue({ deviceId: "owner-device" });
    mocks.listRoles.mockResolvedValue({ roles: [role] });
    mocks.listMembers.mockResolvedValue({
      members: [{ user_id: "member", role_id: role.id, permission_version: 1 }],
    });
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({ checkpoint: { payload: {} } });
    mocks.buildAppend.mockResolvedValue({ events: [{}], checkpoint: { payload: {} } });
    mocks.updateRole.mockResolvedValue({ ok: true, workspaces_needing_kek_rotation: [] });
    mocks.advancePin.mockResolvedValue(undefined);
  });

  it("rebuilds once after a stale key-directory rejection", async () => {
    const ApiError = (await import("@/shared/api")).ApiError;
    mocks.updateRole
      .mockRejectedValueOnce(new ApiError(422, { error: "invalid_key_directory" }))
      .mockResolvedValueOnce({ ok: true, workspaces_needing_kek_rotation: [] });

    await updateWorkspaceRoleWithKeyDirectory({
      workspaceId: "workspace",
      role,
      permissions: [{ permission: "document:write", granted: false }],
    });

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(2);
    expect(mocks.buildAppend).toHaveBeenCalledTimes(2);
    expect(mocks.updateRole).toHaveBeenCalledTimes(2);
    expect(mocks.advancePin).toHaveBeenCalledTimes(1);
  });
});
