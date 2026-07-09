import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import type { DocumentState } from "../../model/document-state/types";

const mocks = vi.hoisted(() => ({
  deviceState: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  fetchVerifiedKeyDirectoryFromTrustedCheckpoint: vi.fn(),
  getDocumentCryptoWorker: vi.fn(),
  getLocalDeviceId: vi.fn(),
  recordSyncPerf: vi.fn(),
  rememberShareWorkspaceCheckpoint: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
  fetchVerifiedKeyDirectoryFromTrustedCheckpoint:
    mocks.fetchVerifiedKeyDirectoryFromTrustedCheckpoint,
}));

vi.mock("./crypto-worker", () => ({
  getDocumentCryptoWorker: mocks.getDocumentCryptoWorker,
}));

vi.mock("./outbound-admission", () => ({
  rememberShareWorkspaceCheckpoint: mocks.rememberShareWorkspaceCheckpoint,
}));

vi.mock("./share-identity", () => ({
  getLocalDeviceId: mocks.getLocalDeviceId,
}));

vi.mock("./perf", () => ({
  recordSyncPerf: mocks.recordSyncPerf,
}));

import { createAdmissionKeyDirectoryRefresh } from "./admission-key-directory";

function documentState(): DocumentState {
  return {
    access: { kind: "user" },
    workspaceId: "workspace-1",
  } as unknown as DocumentState;
}

describe("createAdmissionKeyDirectoryRefresh", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getLocalDeviceId.mockReturnValue("device-1");
  });

  it("forwards trusted checkpoint refresh parameters to the key-directory fetch", async () => {
    const trustedCheckpoint = {
      payload: { sequence: 2 },
      signatures: [],
    } as unknown as SignedKeyDirectoryEnvelope;
    const currentCheckpoint = {
      payload: { sequence: 4 },
      signatures: [],
    };
    mocks.fetchVerifiedKeyDirectoryFromTrustedCheckpoint.mockResolvedValue({
      checkpoint: currentCheckpoint,
    });

    const refresh = createAdmissionKeyDirectoryRefresh(documentState(), "document-1");
    await refresh({ trustedCheckpointEnvelope: trustedCheckpoint });

    expect(mocks.fetchVerifiedKeyDirectory).not.toHaveBeenCalled();
    expect(mocks.fetchVerifiedKeyDirectoryFromTrustedCheckpoint).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId: "workspace-1",
      rrpDeviceId: "device-1",
      popScope: "user",
      popWorker: undefined,
      trustedCheckpointEnvelope: trustedCheckpoint,
    });
    expect(mocks.rememberShareWorkspaceCheckpoint).toHaveBeenCalledWith(
      { kind: "user" },
      currentCheckpoint,
    );
  });
});
