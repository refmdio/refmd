import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  getWorkspaceIds: vi.fn(),
  getWorkspaceKeysWithRrp: vi.fn(),
  getMemberEnvelopeWithRrp: vi.fn(),
  getCryptoWorker: vi.fn(),
  openAdmittedWorkspaceMemberKekEnvelope: vi.fn(),
  getPublicKeys: vi.fn(),
  persistWorkspaceKekLocally: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/kek-resolver", () => ({
  openAdmittedWorkspaceMemberKekEnvelope: mocks.openAdmittedWorkspaceMemberKekEnvelope,
}));

vi.mock("@/shared/api", () => ({
  encryptionApi: {
    getWorkspaceIds: mocks.getWorkspaceIds,
    getWorkspaceKeysWithRrp: mocks.getWorkspaceKeysWithRrp,
    getMemberEnvelopeWithRrp: mocks.getMemberEnvelopeWithRrp,
  },
}));

vi.mock("@/shared/lib/crypto/workspace-kek-persistence", () => ({
  persistWorkspaceKekLocally: mocks.persistWorkspaceKekLocally,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: mocks.getCryptoWorker,
}));

import { ApiError } from "@/shared/api/core";
import { restoreWorkspaceKeks } from "./session-keks";

describe("recovery workspace KEK restoration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getCryptoWorker.mockReturnValue({
      getPublicKeys: mocks.getPublicKeys,
    });
    mocks.getWorkspaceIds.mockResolvedValue({ workspace_ids: ["workspace-1"] });
    mocks.openAdmittedWorkspaceMemberKekEnvelope.mockResolvedValue(undefined);
    mocks.getPublicKeys.mockResolvedValue({
      deviceHybridSigningPublicKeyMaterial: { protocol: "signing-material" },
      deviceHybridEncryptionPublicKeyMaterial: { protocol: "encryption-material" },
    });
    mocks.persistWorkspaceKekLocally.mockResolvedValue(undefined);
  });

  it("uses the current verified workspace directory when persisting the recovered device KEK", async () => {
    mocks.getWorkspaceKeysWithRrp.mockRejectedValue(
      new ApiError(404, {
        error: "not_found",
        details: { current_kek_version: 1 },
      }),
    );
    mocks.getMemberEnvelopeWithRrp.mockResolvedValue({
      key_version: 1,
      sender_hybrid_signing_public_key_material: { protocol: "sender-signing-material" },
      workspace_key_directory_checkpoint: { payload: { sequence: 2 }, signatures: [] },
    });

    const result = await restoreWorkspaceKeks("user-1", "device-1", null, null);

    expect(result).toEqual({ restored: ["workspace-1"], failed: [] });
    expect(mocks.getWorkspaceIds).toHaveBeenCalledWith({ rrpDeviceId: "device-1" });
    expect(mocks.getWorkspaceKeysWithRrp).toHaveBeenCalledWith("workspace-1", "device-1", {
      rrpDeviceId: "device-1",
    });
    expect(mocks.getMemberEnvelopeWithRrp).toHaveBeenCalledWith("workspace-1", {
      rrpDeviceId: "device-1",
    });
    expect(mocks.openAdmittedWorkspaceMemberKekEnvelope).toHaveBeenCalledWith(
      "workspace-1",
      expect.objectContaining({ key_version: 1 }),
    );
    const params = mocks.persistWorkspaceKekLocally.mock.calls[0]?.[0];
    expect(params).toMatchObject({
      workspaceId: "workspace-1",
      userId: "user-1",
      deviceId: "device-1",
      keyVersion: 1,
      isActive: true,
      ignoreConflict: true,
    });
    expect(params).not.toHaveProperty("keyDirectoryCheckpoint");
  });

  it("does not open a member envelope when sender key admission fails", async () => {
    mocks.getWorkspaceKeysWithRrp.mockRejectedValue(
      new ApiError(404, {
        error: "not_found",
        details: { current_kek_version: 1 },
      }),
    );
    mocks.getMemberEnvelopeWithRrp.mockResolvedValue({
      key_version: 1,
      sender_hybrid_signing_public_key_material: { protocol: "sender-signing-material" },
    });
    mocks.openAdmittedWorkspaceMemberKekEnvelope.mockRejectedValue(
      new Error("workspace_sender_signing_key_revoked"),
    );

    const result = await restoreWorkspaceKeks("user-1", "device-1", null, null);

    expect(result).toEqual({
      restored: [],
      failed: ["workspace-1:workspace_sender_signing_key_revoked"],
    });
    expect(mocks.persistWorkspaceKekLocally).not.toHaveBeenCalled();
  });
});
