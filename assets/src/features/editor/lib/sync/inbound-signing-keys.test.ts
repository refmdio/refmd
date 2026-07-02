import { afterEach, describe, expect, it, vi } from "vitest";
import type { DocumentState } from "../../model/document-state/types";
import { resolveSigningKey } from "./inbound-signing-keys";

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

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({}),
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
