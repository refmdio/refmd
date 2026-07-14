import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  getMemberEnvelopeWithRrp: vi.fn(),
  openAdmittedWorkspaceMemberKekEnvelope: vi.fn(),
  getPublicKeys: vi.fn(),
  persistWorkspaceKekForDevice: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  encryptionApi: { getMemberEnvelopeWithRrp: mocks.getMemberEnvelopeWithRrp },
}));

vi.mock("@/shared/lib/crypto/kek-resolver", () => ({
  openAdmittedWorkspaceMemberKekEnvelope: mocks.openAdmittedWorkspaceMemberKekEnvelope,
}));

vi.mock("@/shared/lib/crypto/workspace-kek-persistence", () => ({
  persistWorkspaceKekForDevice: mocks.persistWorkspaceKekForDevice,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({ getPublicKeys: mocks.getPublicKeys }),
}));

import { recoverWorkspaceInvitationMemberEnvelope } from "./member-envelope-recovery";

describe("workspace invitation member-envelope recovery", () => {
  const envelope = {
    key_version: 4,
    sender_hybrid_signing_public_key_material: { protocol: "sender-signing-material" },
  };
  const auth = { user: { id: "user-1" } } as never;
  const device = { deviceId: "device-1" };

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getMemberEnvelopeWithRrp.mockResolvedValue(envelope);
    mocks.openAdmittedWorkspaceMemberKekEnvelope.mockResolvedValue(undefined);
    mocks.getPublicKeys.mockResolvedValue({
      deviceHybridEncryptionPublicKeyMaterial: { protocol: "device-encryption-material" },
    });
    mocks.persistWorkspaceKekForDevice.mockResolvedValue(undefined);
  });

  it("persists the KEK only after the admitted member envelope opens", async () => {
    await recoverWorkspaceInvitationMemberEnvelope("workspace-1", auth, device);

    expect(mocks.openAdmittedWorkspaceMemberKekEnvelope).toHaveBeenCalledWith(
      "workspace-1",
      envelope,
    );
    expect(mocks.persistWorkspaceKekForDevice).toHaveBeenCalledWith({
      workspaceId: "workspace-1",
      userId: "user-1",
      senderDeviceId: "device-1",
      targetDeviceId: "device-1",
      targetDeviceHybridEncryptionPublicKeyMaterial: { protocol: "device-encryption-material" },
      keyVersion: 4,
      ignoreConflict: true,
    });
    expect(mocks.openAdmittedWorkspaceMemberKekEnvelope.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.persistWorkspaceKekForDevice.mock.invocationCallOrder[0] ?? 0,
    );
  });

  it("does not reach Worker key access or persistence when sender admission fails", async () => {
    mocks.openAdmittedWorkspaceMemberKekEnvelope.mockRejectedValue(
      new Error("workspace_sender_signing_key_revoked"),
    );

    await expect(
      recoverWorkspaceInvitationMemberEnvelope("workspace-1", auth, device),
    ).rejects.toThrow("workspace_sender_signing_key_revoked");
    expect(mocks.getPublicKeys).not.toHaveBeenCalled();
    expect(mocks.persistWorkspaceKekForDevice).not.toHaveBeenCalled();
  });
});
