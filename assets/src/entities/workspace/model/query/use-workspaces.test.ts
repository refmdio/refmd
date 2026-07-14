import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  fetchDirectory: vi.fn(),
  list: vi.fn(),
  putOffline: vi.fn(async () => undefined),
  verifyAudit: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: () => ({ user: { id: "user-1" } }),
  deviceState: () => ({ deviceId: "device-1" }),
}));
vi.mock("@/shared/api", () => ({
  workspacesApi: { list: mocks.list },
}));
vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchDirectory,
}));
vi.mock("@/shared/lib/anti-rollback/audit-checkpoint-pin", () => ({
  verifyAndPinAuditCheckpoint: mocks.verifyAudit,
}));
vi.mock("@/shared/lib/offline/storage/store", () => ({
  putOfflineWorkspaces: mocks.putOffline,
}));

import { fetchVerifiedWorkspaces } from "./use-workspaces";

describe("fetchVerifiedWorkspaces", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.list.mockResolvedValue({
      workspaces: [
        {
          id: "workspace-1",
          name: "Workspace",
          description: null,
          slug: "workspace",
          is_default: true,
          updated_at: "2026-07-12T00:00:00Z",
          audit_checkpoint: { sequence: 1 },
        },
      ],
    });
    mocks.fetchDirectory.mockResolvedValue({ checkpoint: {} });
    mocks.verifyAudit.mockResolvedValue({});
  });

  it("verifies key-directory authority before accepting each audit checkpoint", async () => {
    await expect(fetchVerifiedWorkspaces()).resolves.toMatchObject({
      workspaces: [{ id: "workspace-1" }],
    });

    expect(mocks.fetchDirectory).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId: "workspace-1",
      rrpDeviceId: "device-1",
    });
    expect(mocks.fetchDirectory.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.verifyAudit.mock.invocationCallOrder[0]!,
    );
  });

  it("propagates audit verification failures without offline success", async () => {
    mocks.verifyAudit.mockRejectedValue(new Error("audit_checkpoint_rollback_or_fork"));

    await expect(fetchVerifiedWorkspaces()).rejects.toThrow("audit_checkpoint_rollback_or_fork");
    expect(mocks.putOffline).not.toHaveBeenCalled();
  });

  it("propagates key-directory verification failures without offline success", async () => {
    mocks.fetchDirectory.mockRejectedValue(new Error("key_directory_checkpoint_fork"));

    await expect(fetchVerifiedWorkspaces()).rejects.toThrow("key_directory_checkpoint_fork");
    expect(mocks.verifyAudit).not.toHaveBeenCalled();
    expect(mocks.putOffline).not.toHaveBeenCalled();
  });

  it("propagates transport failures without unauthenticated cached workspace data", async () => {
    mocks.list.mockRejectedValue(new Error("network_unavailable"));

    await expect(fetchVerifiedWorkspaces()).rejects.toThrow("network_unavailable");
    expect(mocks.fetchDirectory).not.toHaveBeenCalled();
    expect(mocks.putOffline).not.toHaveBeenCalled();
  });
});
