import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  buildDirectory: vi.fn(),
  create: vi.fn(),
  generateKek: vi.fn(),
  persistLocal: vi.fn(),
  persistMember: vi.fn(),
  pinDirectory: vi.fn(),
  verifyAuditPin: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: () => ({ user: { id: "user-1" } }),
  cryptoWorkerReady: () => true,
  deviceState: () => ({ deviceId: "device-1" }),
}));

vi.mock("@/shared/api", () => ({
  workspacesApi: {
    create: mocks.create,
  },
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    generateKek: mocks.generateKek,
    getPublicKeys: vi.fn(async () => ({
      identityHybridSigningPublicKeyMaterial: { owner_kind: "identity" },
      identityHybridEncryptionPublicKeyMaterial: { owner_kind: "identity" },
      deviceHybridSigningPublicKeyMaterial: { owner_kind: "device" },
      deviceHybridEncryptionPublicKeyMaterial: { owner_kind: "device" },
    })),
  }),
}));

vi.mock("@/shared/lib/crypto/key-directory/initial", () => ({
  buildInitialWorkspaceKeyDirectoryBootstrap: mocks.buildDirectory,
}));

vi.mock("@/shared/lib/anti-rollback/audit-checkpoint-pin", () => ({
  verifyAndPinAuditCheckpoint: mocks.verifyAuditPin,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  pinInitialKeyDirectoryCheckpoint: mocks.pinDirectory,
}));

vi.mock("@/shared/lib/crypto/workspace-kek-persistence", () => ({
  persistWorkspaceKekForMember: mocks.persistMember,
  persistWorkspaceKekLocally: mocks.persistLocal,
}));

import { createWorkspaceWithInitialKek } from "./crud";

describe("workspace creation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.buildDirectory.mockResolvedValue({
      workspaceEvents: [{ payload: {}, signatures: [] }],
      workspaceCheckpoint: { payload: {}, signatures: [] },
    });
    mocks.create.mockResolvedValue({
      id: "workspace-1",
      audit_checkpoint: { chain_scope: "workspace:workspace-1", sequence: 1 },
    });
    mocks.verifyAuditPin.mockResolvedValue(undefined);
    mocks.generateKek.mockResolvedValue({ keyVersion: 1 });
    mocks.persistLocal.mockResolvedValue(undefined);
    mocks.pinDirectory.mockResolvedValue(undefined);
    mocks.persistMember.mockResolvedValue(undefined);
  });

  it("pins the workspace authority before audit verification and KEK persistence", async () => {
    await expect(createWorkspaceWithInitialKek({ name: "Workspace" })).resolves.toBe("workspace-1");

    expect(mocks.pinDirectory).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId: "workspace-1",
      eventEnvelopes: [{ payload: {}, signatures: [] }],
      checkpointEnvelope: { payload: {}, signatures: [] },
    });
    expect(mocks.verifyAuditPin).toHaveBeenCalledWith({
      chain_scope: "workspace:workspace-1",
      sequence: 1,
    });
    expect(mocks.pinDirectory.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.verifyAuditPin.mock.invocationCallOrder[0],
    );
    expect(mocks.verifyAuditPin.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.generateKek.mock.invocationCallOrder[0],
    );
    expect(mocks.generateKek.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.persistLocal.mock.invocationCallOrder[0],
    );
    expect(mocks.persistLocal.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.persistMember.mock.invocationCallOrder[0],
    );
    expect(mocks.persistMember).toHaveBeenCalledWith(
      expect.not.objectContaining({ ignoreConflict: true }),
    );
  });

  it("does not create KEK wraps when audit authority verification fails", async () => {
    mocks.verifyAuditPin.mockRejectedValueOnce(new Error("audit_checkpoint_authority_unverified"));

    await expect(createWorkspaceWithInitialKek({ name: "Workspace" })).rejects.toThrow(
      "audit_checkpoint_authority_unverified",
    );

    expect(mocks.pinDirectory).toHaveBeenCalledOnce();
    expect(mocks.generateKek).not.toHaveBeenCalled();
    expect(mocks.persistLocal).not.toHaveBeenCalled();
    expect(mocks.persistMember).not.toHaveBeenCalled();
  });

  it("does not expose the workspace when owner envelope persistence fails", async () => {
    mocks.persistMember.mockRejectedValueOnce(new Error("member_envelope_conflict"));

    await expect(createWorkspaceWithInitialKek({ name: "Workspace" })).rejects.toThrow(
      "member_envelope_conflict",
    );

    expect(mocks.persistLocal).toHaveBeenCalledOnce();
    expect(mocks.persistMember).toHaveBeenCalledOnce();
  });
});
