import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  listMemberDevices: vi.fn(),
  removeMember: vi.fn(),
  buildWorkspaceMemberRemovalKeyDirectoryAppend: vi.fn(),
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
    listMemberDevices: mocks.listMemberDevices,
    removeMember: mocks.removeMember,
  },
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/crypto/key-directory/membership-events", () => ({
  buildWorkspaceMemberRemovalKeyDirectoryAppend:
    mocks.buildWorkspaceMemberRemovalKeyDirectoryAppend,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advanceKeyDirectoryPinWithProof,
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
    mocks.listMemberDevices.mockResolvedValue({
      devices: [
        {
          signing_key_id: "signing-key",
          encryption_key_id: "encryption-key",
        },
      ],
    });
    mocks.buildWorkspaceMemberRemovalKeyDirectoryAppend.mockResolvedValue({
      events: [{ payload: { event_type: "member_removed" } }],
      checkpoint: { payload: { sequence: 2 } },
    });
    mocks.removeMember.mockResolvedValue({ ok: true, workspaces_needing_kek_rotation: [] });
    mocks.advanceKeyDirectoryPinWithProof.mockResolvedValue(undefined);
  });

  it("does not block self-leave completion on local workspace pin advancement", async () => {
    mocks.advanceKeyDirectoryPinWithProof.mockRejectedValue(new Error("pin advance failed"));

    await expect(
      removeWorkspaceMemberWithKeyDirectory("workspace-1", "user-self"),
    ).resolves.toEqual({
      ok: true,
      workspaces_needing_kek_rotation: [],
    });
    expect(mocks.advanceKeyDirectoryPinWithProof).toHaveBeenCalledTimes(1);
  });

  it("requires local workspace pin advancement when removing another member", async () => {
    mocks.advanceKeyDirectoryPinWithProof.mockRejectedValue(new Error("pin advance failed"));

    await expect(
      removeWorkspaceMemberWithKeyDirectory("workspace-1", "user-other"),
    ).rejects.toThrow("pin advance failed");
  });

  it("rebuilds the member-removal append once when the server rejects a stale key directory", async () => {
    const staleDirectory = { checkpoint: { payload: { sequence: 1 } } };
    const freshDirectory = { checkpoint: { payload: { sequence: 2 } } };
    const staleAppend = {
      events: [{ payload: { event_type: "member_removed", sequence: 2 } }],
      checkpoint: { payload: { sequence: 2 } },
    };
    const freshAppend = {
      events: [{ payload: { event_type: "member_removed", sequence: 3 } }],
      checkpoint: { payload: { sequence: 3 } },
    };
    const InvalidKeyDirectory = (await import("@/shared/api")).ApiError;
    mocks.fetchVerifiedKeyDirectory
      .mockResolvedValueOnce(staleDirectory)
      .mockResolvedValueOnce(freshDirectory);
    mocks.buildWorkspaceMemberRemovalKeyDirectoryAppend
      .mockResolvedValueOnce(staleAppend)
      .mockResolvedValueOnce(freshAppend);
    mocks.removeMember
      .mockRejectedValueOnce(new InvalidKeyDirectory(422, { error: "invalid_key_directory" }))
      .mockResolvedValueOnce({ ok: true, workspaces_needing_kek_rotation: [] });

    await expect(
      removeWorkspaceMemberWithKeyDirectory("workspace-1", "user-self"),
    ).resolves.toEqual({
      ok: true,
      workspaces_needing_kek_rotation: [],
    });

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(2);
    expect(mocks.buildWorkspaceMemberRemovalKeyDirectoryAppend).toHaveBeenCalledTimes(2);
    expect(mocks.removeMember).toHaveBeenNthCalledWith(1, "workspace-1", "user-self", {
      workspace_key_directory_events: staleAppend.events,
      workspace_key_directory_checkpoint: staleAppend.checkpoint,
    });
    expect(mocks.removeMember).toHaveBeenNthCalledWith(2, "workspace-1", "user-self", {
      workspace_key_directory_events: freshAppend.events,
      workspace_key_directory_checkpoint: freshAppend.checkpoint,
    });
  });

  it("does not retry non-key-directory member removal errors", async () => {
    const ApiError = (await import("@/shared/api")).ApiError;
    mocks.removeMember.mockRejectedValue(new ApiError(403, { error: "permission_denied" }));

    await expect(
      removeWorkspaceMemberWithKeyDirectory("workspace-1", "user-other"),
    ).rejects.toThrow("permission_denied");

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(1);
    expect(mocks.removeMember).toHaveBeenCalledTimes(1);
  });
});
