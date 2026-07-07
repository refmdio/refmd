import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import {
  prepareInitializationSession,
  refreshWorkspaceKeyDirectoryForDocumentJoin,
} from "./bootstrap-prepare";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";

const mocks = vi.hoisted(() => ({
  buildDocumentSigningKeyCachesForInitialPayload: vi.fn(),
  buildDocumentSigningKeyCaches: vi.fn(),
  deviceState: vi.fn(),
  ensurePhoenixWsToken: vi.fn(),
  ensureSharedDekCached: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  getCachedWorkspaceDirectory: vi.fn(),
  getKeyDirectoryPin: vi.fn(),
  getLocalSigningKeyId: vi.fn(),
  recordSyncPerf: vi.fn(),
  refreshSharedDocumentAccess: vi.fn(),
  rememberShareWorkspaceCheckpoint: vi.fn(),
  setDocumentReadOnly: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  deviceState: mocks.deviceState,
  getKekResolverSession: vi.fn(),
}));

vi.mock("@/shared/api/encryption", () => ({
  encryptionApi: {
    getDocumentKeys: vi.fn(),
  },
}));

vi.mock("@/shared/lib/auth/pop", () => ({
  buildChannelPopResource: vi.fn(),
  getChannelPopParams: vi.fn(),
}));

vi.mock("@/shared/lib/anti-rollback/document-state-pins", () => ({
  buildDocumentStatePinKey: vi.fn((documentId: string, shareId?: string) =>
    shareId ? `${documentId}:${shareId}` : documentId,
  ),
  getDocumentStatePin: vi.fn(async () => null),
  hasCompleteSnapshotPin: vi.fn(() => false),
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: vi.fn(),
  getKeyDirectoryPin: mocks.getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope: vi.fn(
    (envelope: KeyDirectoryEnvelope) => `checkpoint-${envelope.payload.sequence}`,
  ),
  verifyAndRememberKeyDirectoryLineageFromTrustedAnchor: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/encoding", () => ({
  base64UrlDecode: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/kek-resolver", () => ({
  resolveActiveKek: vi.fn(),
  resolveKekByVersion: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: vi.fn(() => ({})),
}));

vi.mock("@/shared/lib/crypto/worker/scoped", () => ({
  getShareParticipantCryptoWorker: vi.fn(() => ({})),
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/ws/socket", () => ({
  ensurePhoenixWsToken: mocks.ensurePhoenixWsToken,
}));

vi.mock("../../model/document-state/signals", () => ({
  setDocumentReadOnly: mocks.setDocumentReadOnly,
}));

vi.mock("./inbound-signing-keys", () => ({
  applyDeviceKeyCache: vi.fn(),
  buildDeviceKeyCaches: vi.fn(),
  buildDocumentSigningKeyCaches: mocks.buildDocumentSigningKeyCaches,
  buildDocumentSigningKeyCachesForInitialPayload:
    mocks.buildDocumentSigningKeyCachesForInitialPayload,
}));

vi.mock("./bootstrap-key-rotation", () => ({
  completeDekRotationIfNeeded: vi.fn(),
}));

vi.mock("./bootstrap-post-init", () => ({
  primeHistoricalDeks: vi.fn(),
}));

vi.mock("./share-access", () => ({
  ensureSharedDekCached: mocks.ensureSharedDekCached,
  refreshSharedDocumentAccess: mocks.refreshSharedDocumentAccess,
}));

vi.mock("./outbound-admission", () => ({
  getCachedWorkspaceDirectory: mocks.getCachedWorkspaceDirectory,
  rememberShareWorkspaceCheckpoint: mocks.rememberShareWorkspaceCheckpoint,
}));

vi.mock("./share-identity", () => ({
  getLocalSigningKeyId: mocks.getLocalSigningKeyId,
}));

vi.mock("./perf", () => ({
  recordSyncPerf: mocks.recordSyncPerf,
}));

describe("prepareInitializationSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.deviceState.mockReturnValue({
      deviceId: "device-1",
      deviceSigningKeyId: "local-signing-key",
    });
    mocks.ensurePhoenixWsToken.mockResolvedValue(undefined);
    mocks.ensureSharedDekCached.mockResolvedValue(undefined);
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({ checkpoint: checkpoint(1) });
    mocks.getCachedWorkspaceDirectory.mockResolvedValue({ checkpoint: checkpoint(1) });
    mocks.getKeyDirectoryPin.mockResolvedValue({
      pinKey: "workspace:workspace-1",
      scopeKind: "workspace",
      scopeId: "workspace-1",
      checkpointSequence: 1,
      checkpointHash: "checkpoint-1",
      eventHeadSequence: 1,
      eventHeadHash: "event-1",
      suitePolicyVersion: 1,
      minSuiteRank: 1,
      allowedSuiteIdsHash: "suite-policy",
      observedAt: 1,
    });
    mocks.getLocalSigningKeyId.mockReturnValue(undefined);
    mocks.refreshSharedDocumentAccess.mockImplementation(async (state: { access: unknown }) => {
      return state.access;
    });
    mocks.buildDocumentSigningKeyCaches.mockResolvedValue(deviceKeyCache());
    mocks.buildDocumentSigningKeyCachesForInitialPayload.mockResolvedValue(deviceKeyCache());
  });

  it("waits for share workspace pin readiness before building initial payload signing keys", async () => {
    const workspacePinReady = promiseWithResolvers<void>();
    const state = {
      stateKey: "state-1",
      access: {
        kind: "share",
        shareId: "share-1",
        shareSlug: "share-slug",
        participantDeviceId: "share-device-1",
        keyVersion: 1,
        workspaceKeyDirectoryCheckpoint: checkpoint(1),
        workspaceKeyDirectoryLatestCheckpoint: checkpoint(1),
        workspaceKeyDirectoryCheckpointAncestry: [],
        workspaceKeyDirectoryEventAncestry: [],
        workspacePinReady: workspacePinReady.promise,
        initialDocument: { type: "initial_document" },
        permission: "edit",
      },
    };

    const prepared = await prepareInitializationSession(
      "document-1",
      "workspace-1",
      state as never,
      new AbortController().signal,
      () => {},
    );

    await flushPromises();
    expect(mocks.buildDocumentSigningKeyCachesForInitialPayload).not.toHaveBeenCalled();

    workspacePinReady.resolve();
    await expect(prepared.preDocumentReadyPromise).resolves.toEqual({ ready: true });
    expect(mocks.buildDocumentSigningKeyCachesForInitialPayload).toHaveBeenCalledTimes(1);
  });

  it("waits for refreshed share workspace pin readiness before fetching retry key directory", async () => {
    const refreshedWorkspacePinReady = promiseWithResolvers<void>();
    const state = {
      stateKey: "state-1",
      access: {
        kind: "share",
        shareSlug: "share-slug",
        participantDeviceId: "share-device-1",
        workspacePinReady: Promise.resolve(),
      },
    };
    mocks.refreshSharedDocumentAccess.mockImplementationOnce(
      async (refreshState: { access: unknown }) => {
        refreshState.access = {
          kind: "share",
          shareSlug: "share-slug",
          participantDeviceId: "share-device-1",
          workspacePinReady: refreshedWorkspacePinReady.promise,
        };
        return refreshState.access;
      },
    );

    const refresh = refreshWorkspaceKeyDirectoryForDocumentJoin(
      state as never,
      "workspace-1",
      new AbortController().signal,
    );

    await flushPromises();
    expect(mocks.fetchVerifiedKeyDirectory).not.toHaveBeenCalled();

    refreshedWorkspacePinReady.resolve();
    await refresh;
    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledTimes(1);
  });
});

function checkpoint(sequence: number): KeyDirectoryEnvelope {
  return {
    payload: {
      sequence,
      covered_event_head: {
        head_sequence: sequence,
        head_hash: `event-${sequence}`,
      },
    },
    signatures: [],
  } as unknown as KeyDirectoryEnvelope;
}

function deviceKeyCache() {
  return {
    status: "ok" as const,
    signingKeys: new Map(),
    historicalSigningKeys: new Map(),
    signingKeyOwners: new Map(),
  };
}

async function flushPromises(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function promiseWithResolvers<T>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}
