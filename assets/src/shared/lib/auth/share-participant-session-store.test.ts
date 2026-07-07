import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const worker = vi.hoisted(() => ({
  clearShareParticipantSessionsWithDsk: vi.fn(),
  deleteShareParticipantSessionWithDsk: vi.fn(),
  listShareParticipantSessionsWithDsk: vi.fn(),
  loadStoredDsk: vi.fn(),
  storeShareParticipantSessionWithDsk: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => worker,
}));

vi.mock("@/shared/lib/crypto/worker/scoped", () => ({
  getShareParticipantCryptoWorker: () => worker,
}));

import {
  clearStoredShareParticipantSessions,
  deleteStoredShareParticipantSession,
  listStoredShareParticipantSessions,
  writeStoredShareParticipantSession,
  type StoredShareParticipantSession,
} from "./share-participant-session-store";
import { encodeBase64Url } from "@/shared/lib/crypto/encoding";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";

describe("share participant session store cleanup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    worker.loadStoredDsk.mockResolvedValue(true);
  });

  it("stores sessions through worker-owned DSK storage and updates the index", async () => {
    await writeStoredShareParticipantSession(session("share-token"));

    expect(worker.storeShareParticipantSessionWithDsk).toHaveBeenCalledWith(session("share-token"));
    expect(worker.loadStoredDsk).toHaveBeenCalled();
  });

  it("lists sessions through the DSK index", async () => {
    worker.listShareParticipantSessionsWithDsk.mockResolvedValueOnce([session("share-a")]);

    await expect(listStoredShareParticipantSessions()).resolves.toEqual([session("share-a")]);
  });

  it("deletes a stored share participant session and removes it from the DSK index", async () => {
    await deleteStoredShareParticipantSession("share-token");

    expect(worker.deleteShareParticipantSessionWithDsk).toHaveBeenCalledWith("share-token");
  });

  it("clears all indexed stored share participant sessions", async () => {
    await clearStoredShareParticipantSessions();

    expect(worker.clearShareParticipantSessionsWithDsk).toHaveBeenCalled();
  });
});

function session(shareSlug: string): StoredShareParticipantSession {
  const deviceId = "018f6a57-6ff4-4f2b-b3d4-2c907f5b6b11";
  const hybridSigningPublicKeyMaterial = {
    protocol: "refmd.hybrid-signing-key-material",
    version: 1,
    owner_kind: "share_participant_device",
    owner_id: deviceId,
    suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
    suite_rank: 1000,
    ed25519_public: encodeBase64Url(new Uint8Array(32)),
    mldsa65_public: encodeBase64Url(new Uint8Array(1952)),
  } satisfies StoredShareParticipantSession["hybridSigningPublicKeyMaterial"];

  return {
    shareSlug,
    shareId: "share-id",
    principalId: "principal",
    deviceId,
    sessionId: "session",
    redeemAttemptId: "session",
    displayName: "Guest",
    signingKeyId: computeSigningKeyId(hybridSigningPublicKeyMaterial),
    hybridSigningPublicKeyMaterial,
    encryptionPublicKey: "encryption",
    passwordProtected: false,
  };
}
