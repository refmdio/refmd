import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  create: vi.fn(),
  createAuthorization: vi.fn(),
  createIntent: vi.fn(),
  createPrecommit: vi.fn(),
  generateKek: vi.fn(),
  materializeDirectory: vi.fn(),
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
    createIntent: mocks.createIntent,
  },
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    generateKek: mocks.generateKek,
    createGenesisWorkspaceMemberEnvelopePrecommit: mocks.createPrecommit,
    getPublicKeys: vi.fn(async () => ({
      identityHybridSigningPublicKeyMaterial: { owner_kind: "identity" },
      identityHybridEncryptionPublicKeyMaterial: { owner_kind: "identity" },
      deviceHybridSigningPublicKeyMaterial: { owner_kind: "device" },
      deviceHybridEncryptionPublicKeyMaterial: { owner_kind: "device" },
    })),
  }),
}));

vi.mock("@/shared/lib/crypto/genesis-authorization", () => ({
  createWorkspaceGenesisAuthorization: mocks.createAuthorization,
  materializeWorkspaceGenesisKeyDirectory: mocks.materializeDirectory,
}));

vi.mock("@/shared/lib/anti-rollback/audit-checkpoint-pin", () => ({
  verifyAndPinAuditCheckpoint: mocks.verifyAuditPin,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  pinInitialKeyDirectoryCheckpoint: mocks.pinDirectory,
}));

import { createWorkspaceWithInitialKek } from "./crud";

describe("workspace creation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.createPrecommit.mockResolvedValue({ protocol: "refmd.workspace-member-envelope" });
    mocks.createIntent.mockResolvedValue({ protocol: "refmd.audit.compound-append-intent" });
    mocks.createAuthorization.mockResolvedValue({
      protocol: "refmd.audit.compound-append-authorization",
    });
    mocks.materializeDirectory.mockReturnValue({
      workspaceEvents: [{ payload: {}, signatures: [] }],
      workspaceCheckpoint: { payload: {}, signatures: [] },
    });
    mocks.create.mockImplementation(async () => ({
      workspace_id: mocks.createIntent.mock.calls[0]?.[0]?.workspace_id,
      workspace_audit_checkpoint: { chain_scope_kind: "workspace", sequence: 1 },
    }));
    mocks.verifyAuditPin.mockResolvedValue(undefined);
    mocks.generateKek.mockResolvedValue({ keyVersion: 1 });
    mocks.pinDirectory.mockResolvedValue(undefined);
  });

  it("prepares, signs, and commits before pinning the exact workspace genesis", async () => {
    mocks.create.mockImplementationOnce(async () => {
      const command = mocks.createIntent.mock.calls[0]?.[0];
      return {
        workspace_id: command.workspace_id,
        workspace_audit_checkpoint: { chain_scope_kind: "workspace", sequence: 1 },
      };
    });
    const result = await createWorkspaceWithInitialKek({ name: "Workspace" });
    expect(result).toBe(mocks.createIntent.mock.calls[0]?.[0]?.workspace_id);

    expect(mocks.pinDirectory).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId: expect.any(String),
      eventEnvelopes: [{ payload: {}, signatures: [] }],
      checkpointEnvelope: { payload: {}, signatures: [] },
    });
    expect(mocks.verifyAuditPin).toHaveBeenCalledWith({
      chain_scope_kind: "workspace",
      sequence: 1,
    });
    expect(mocks.generateKek.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.createPrecommit.mock.invocationCallOrder[0],
    );
    expect(mocks.createPrecommit.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.createIntent.mock.invocationCallOrder[0],
    );
    expect(mocks.createIntent.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.createAuthorization.mock.invocationCallOrder[0],
    );
    expect(mocks.createAuthorization.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.create.mock.invocationCallOrder[0],
    );
    expect(mocks.create.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.pinDirectory.mock.invocationCallOrder[0],
    );
    expect(mocks.pinDirectory.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.verifyAuditPin.mock.invocationCallOrder[0],
    );
  });

  it("does not continue after committed audit authority verification fails", async () => {
    mocks.create.mockImplementationOnce(async () => {
      const command = mocks.createIntent.mock.calls[0]?.[0];
      return {
        workspace_id: command.workspace_id,
        workspace_audit_checkpoint: { chain_scope_kind: "workspace", sequence: 1 },
      };
    });
    mocks.verifyAuditPin.mockRejectedValueOnce(new Error("audit_checkpoint_authority_unverified"));

    await expect(createWorkspaceWithInitialKek({ name: "Workspace" })).rejects.toThrow(
      "audit_checkpoint_authority_unverified",
    );

    expect(mocks.create).toHaveBeenCalledOnce();
    expect(mocks.pinDirectory).toHaveBeenCalledOnce();
  });

  it("does not pin any workspace state when the atomic commit fails", async () => {
    mocks.create.mockRejectedValueOnce(new Error("member_envelope_conflict"));

    await expect(createWorkspaceWithInitialKek({ name: "Workspace" })).rejects.toThrow(
      "member_envelope_conflict",
    );

    expect(mocks.pinDirectory).not.toHaveBeenCalled();
    expect(mocks.verifyAuditPin).not.toHaveBeenCalled();
  });
});
