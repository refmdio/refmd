import { afterEach, describe, expect, it, vi } from "vitest";
import type { DocumentState } from "../../model/document-state/types";
import { buildDeviceKeyCaches, resolveSigningKey } from "./inbound-signing-keys";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  deviceState: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  getShareVerificationDirectory: vi.fn(),
  listMembers: vi.fn(),
  listMemberDevices: vi.fn(),
  recordSyncPerf: vi.fn(),
  refreshSharedDocumentAccess: vi.fn(),
  verifyWorkspaceDirectoryDeviceIdentity: vi.fn(),
  cryptoWorker: {
    tofuVerify: vi.fn(),
    tofuHandleResult: vi.fn(),
  },
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/api/core", () => ({
  ApiError: class ApiError extends Error {
    status: number;

    constructor(status: number, message = "api_error") {
      super(message);
      this.status = status;
    }
  },
}));

vi.mock("@/shared/api/workspaces", () => ({
  workspacesApi: {
    listMembers: mocks.listMembers,
    listMemberDevices: mocks.listMemberDevices,
  },
}));

vi.mock("@/shared/api/shares", () => ({
  sharesApi: {
    getDocumentShareVerificationDirectory: mocks.getShareVerificationDirectory,
  },
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/document/share-verification-directory", () => ({
  normalizeShareVerificationDirectory: (directory: unknown) => directory,
}));

vi.mock("@/shared/lib/crypto/signature", () => ({
  computeSigningKeyId: (material: { keyId?: string; owner_kind?: string; owner_id?: string }) =>
    material.keyId ?? `${material.owner_kind}:${material.owner_id}`,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => mocks.cryptoWorker,
}));

vi.mock("./share-access", () => ({
  refreshSharedDocumentAccess: mocks.refreshSharedDocumentAccess,
}));

vi.mock("./inbound-workspace-device-approval", () => ({
  verifyWorkspaceDirectoryDeviceIdentity: mocks.verifyWorkspaceDirectoryDeviceIdentity,
}));

vi.mock("./perf", () => ({
  recordSyncPerf: mocks.recordSyncPerf,
}));

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("inbound signing key refresh", () => {
  it("deduplicates forced workspace and share directory refreshes during unknown signer retries", async () => {
    vi.useFakeTimers();
    mocks.authState.mockReturnValue({ user: { accountType: "guest" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({
      checkpoint: { payload: { device_keys: [], identity_keys: [] } },
    });
    mocks.getShareVerificationDirectory.mockResolvedValue({
      workspace_devices: [],
      share_participant_devices: [],
    });

    const result = resolveSigningKey("missing-signing-key", workspaceDocumentState());
    await vi.runAllTimersAsync();

    await expect(result).resolves.toEqual({ status: "not_found" });
    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(1);
    expect(mocks.getShareVerificationDirectory).toHaveBeenCalledTimes(1);
    expect(mocks.listMembers).not.toHaveBeenCalled();
    expect(mocks.listMemberDevices).not.toHaveBeenCalled();
  });

  it("allows first-seen identity for workspace devices from document verification directories", async () => {
    const signingMaterial = {
      protocol: "refmd.hybrid-signing-key-material",
      owner_kind: "device",
      owner_id: "device-two",
      keyId: "signing-two",
    };
    const identitySigningMaterial = {
      protocol: "refmd.hybrid-signing-key-material",
      owner_kind: "identity",
      owner_id: "user-one",
      keyId: "identity-one",
    };
    const encryptionMaterial = {
      x25519_public: "AA",
    };

    mocks.authState.mockReturnValue({ user: { accountType: "user" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({
      checkpoint: { payload: { device_keys: [], identity_keys: [] } },
    });
    mocks.listMembers.mockResolvedValue({
      members: [{ user_id: "user-one", name: "User One" }],
    });
    mocks.listMemberDevices.mockResolvedValue({ devices: [] });
    mocks.getShareVerificationDirectory.mockResolvedValue({
      workspace_devices: [
        {
          device_id: "device-two",
          user_id: "user-one",
          hybrid_signing_public_key_material: signingMaterial,
          signing_key_id: "signing-two",
          hybrid_encryption_public_key_material: encryptionMaterial,
          encryption_key_id: "encryption-two",
          identity_hybrid_signing_public_key_material: identitySigningMaterial,
          identity_hybrid_encryption_public_key_material: encryptionMaterial,
          approval_signature: {},
          approval_signature_surface: "device_approval",
          approval_proof: {},
          client_nonce: "AA",
        },
      ],
      share_participant_devices: [],
    });
    mocks.verifyWorkspaceDirectoryDeviceIdentity.mockResolvedValue(false);
    mocks.cryptoWorker.tofuVerify.mockResolvedValue({ status: "first_seen" });
    mocks.cryptoWorker.tofuHandleResult.mockResolvedValue(undefined);

    const result = await buildDeviceKeyCaches("workspace-one", undefined, "document-one", true);

    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(result.signingKeys.has("signing-two")).toBe(true);
    expect(mocks.verifyWorkspaceDirectoryDeviceIdentity).toHaveBeenCalledWith(
      expect.objectContaining({ device_id: "device-two", user_id: "user-one" }),
      mocks.cryptoWorker,
      expect.objectContaining({
        namespace: "refmd.v2.workspace:workspace-one",
        allowFirstSeenIdentity: true,
      }),
    );
    expect(mocks.cryptoWorker.tofuVerify).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "user-one",
        deviceId: "device-two",
        namespace: "refmd.v2.workspace:workspace-one",
      }),
    );
  });

  it("verifies genesis workspace directory devices before approved devices", async () => {
    const verificationOrder: string[] = [];
    const encryptionMaterial = { x25519_public: "AA" };
    const deviceOneSigningMaterial = {
      protocol: "refmd.hybrid-signing-key-material",
      owner_kind: "device",
      owner_id: "device-one",
      keyId: "signing-one",
    };

    mocks.authState.mockReturnValue({ user: { accountType: "user" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({
      checkpoint: {
        payload: {
          device_keys: [
            {
              key_id: "signing-one",
              key_material: deviceOneSigningMaterial,
            },
          ],
          identity_keys: [],
        },
      },
    });
    mocks.listMembers.mockResolvedValue({
      members: [{ user_id: "user-one", name: "User One" }],
    });
    mocks.listMemberDevices.mockResolvedValue({ devices: [] });
    mocks.getShareVerificationDirectory.mockResolvedValue({
      workspace_devices: [
        {
          device_id: "device-two",
          user_id: "user-one",
          hybrid_signing_public_key_material: {
            protocol: "refmd.hybrid-signing-key-material",
            owner_kind: "device",
            owner_id: "device-two",
            keyId: "signing-two",
          },
          signing_key_id: "signing-two",
          hybrid_encryption_public_key_material: encryptionMaterial,
          encryption_key_id: "encryption-two",
          identity_hybrid_signing_public_key_material: {
            protocol: "refmd.hybrid-signing-key-material",
            owner_kind: "identity",
            owner_id: "user-one",
            keyId: "identity-one",
          },
          identity_hybrid_encryption_public_key_material: encryptionMaterial,
          approval_signature: {},
          approval_signature_surface: "device_approval",
          approval_proof: {},
          client_nonce: "AA",
        },
        {
          device_id: "device-one",
          user_id: "user-one",
          hybrid_signing_public_key_material: deviceOneSigningMaterial,
          signing_key_id: "signing-one",
          hybrid_encryption_public_key_material: encryptionMaterial,
          encryption_key_id: "encryption-one",
          identity_hybrid_signing_public_key_material: {
            protocol: "refmd.hybrid-signing-key-material",
            owner_kind: "identity",
            owner_id: "user-one",
            keyId: "identity-one",
          },
          identity_hybrid_encryption_public_key_material: encryptionMaterial,
          approval_signature: {},
          approval_signature_surface: "genesis_device_bootstrap",
          approval_proof: {},
          client_nonce: "AA",
        },
      ],
      share_participant_devices: [],
    });
    mocks.verifyWorkspaceDirectoryDeviceIdentity.mockImplementation(
      (
        device: { device_id: string },
        _worker: unknown,
        options?: { approvalSigningKeys?: ReadonlyMap<string, unknown> },
      ) => {
        verificationOrder.push(device.device_id);
        if (device.device_id === "device-two") {
          expect(options?.approvalSigningKeys?.has("signing-one")).toBe(true);
        }
        return Promise.resolve(false);
      },
    );
    mocks.cryptoWorker.tofuVerify.mockResolvedValue({ status: "first_seen" });
    mocks.cryptoWorker.tofuHandleResult.mockResolvedValue(undefined);

    const result = await buildDeviceKeyCaches("workspace-order", undefined, "document-order", true);

    expect(result.status).toBe("ok");
    expect(verificationOrder).toEqual(["device-one", "device-two"]);
  });
});

let nextStateId = 0;

function workspaceDocumentState(): DocumentState {
  nextStateId += 1;
  return {
    access: { kind: "workspace" },
    documentId: `document-${nextStateId}`,
    workspaceId: `workspace-${nextStateId}`,
    signingKeys: new Map(),
    historicalSigningKeys: new Map(),
    signingKeyOwners: new Map(),
    memberNames: new Map(),
    revokedSigningKeys: new Set(),
    rejectedSigningKeys: new Set(),
  } as unknown as DocumentState;
}
