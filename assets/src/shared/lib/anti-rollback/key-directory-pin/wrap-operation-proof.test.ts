import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const pins = vi.hoisted(() => ({
  advance: vi.fn(),
  get: vi.fn(),
  hasCheckpoint: vi.fn(),
  hasEvent: vi.fn(),
  hydrate: vi.fn(),
  remember: vi.fn(),
  checkpoints: vi.fn(),
  events: vi.fn(),
}));

vi.mock("./pins", () => ({
  advanceKeyDirectoryPinWithProof: pins.advance,
  getKeyDirectoryPin: pins.get,
  hasVerifiedKeyDirectoryCheckpoint: pins.hasCheckpoint,
  hasVerifiedKeyDirectoryEvent: pins.hasEvent,
  hydrateVerifiedKeyDirectoryLineage: pins.hydrate,
  rememberVerifiedKeyDirectoryLineage: pins.remember,
  lookupVerifiedKeyDirectoryCheckpointBodies: pins.checkpoints,
  lookupVerifiedKeyDirectoryEventBodies: pins.events,
}));

import { checkpointHash, eventHash } from "./primitives";
import type { KeyDirectoryPin, SignedKeyDirectoryEnvelope } from "./types";
import { verifyWorkspaceSignedPqWrapOperation } from "./wrap-operation-proof";
import {
  createSignedPqWrap,
  finalizeSignedPqWrapOperationCheckpoint,
  signedPqWrapEventBody,
  type SignedPqWrapRecord,
} from "@/shared/lib/crypto/signed-pq-wrap";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  generateHybridEncryptionPrivateKeyMaterial,
  publicHybridEncryptionMaterialFromPrivate,
} from "@/shared/lib/crypto/hybrid-encryption";
import { generateHybridSigningPrivateKeyMaterial } from "@/shared/lib/crypto/signature";
import { eventHead, keyDirectoryCheckpoint } from "@/shared/lib/crypto/key-directory/primitives";
import { wrapIssuedKeyDirectoryEventFromRecord } from "@/shared/lib/crypto/key-directory/wrap-events";

const HASH_A = "F3Yv3dlppFOSXWVxesPuohMgtmtUNC_eFRKNbK8hIV8";
const HASH_B = "EOXPPTyKT580aMjMWO6oSJKiL9rbwayyJBAZAETB1VM";

interface Fixture {
  workspaceId: string;
  record: SignedPqWrapRecord;
  event: SignedKeyDirectoryEnvelope;
  checkpoint: SignedKeyDirectoryEnvelope;
  container: Record<string, unknown>;
}

let verifiedCheckpoints: SignedKeyDirectoryEnvelope[];
let verifiedEvents: SignedKeyDirectoryEnvelope[];
let currentPin: KeyDirectoryPin;

describe("workspace Signed PQ wrap operation proof", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    verifiedCheckpoints = [];
    verifiedEvents = [];
    pins.get.mockImplementation(async () => currentPin);
    pins.checkpoints.mockImplementation(() => verifiedCheckpoints);
    pins.events.mockImplementation(() => verifiedEvents);
    pins.hasCheckpoint.mockImplementation((_kind, _id, sequence, hash) =>
      verifiedCheckpoints.some(
        (entry) => entry.payload.sequence === sequence && checkpointHash(entry) === hash,
      ),
    );
    pins.hasEvent.mockImplementation((_kind, _id, sequence, hash) =>
      verifiedEvents.some(
        (entry) => entry.payload.sequence === sequence && eventHash(entry) === hash,
      ),
    );
    pins.hydrate.mockResolvedValue(undefined);
  });

  it("accepts an operation checkpoint equal to the current pin", async () => {
    const fixture = buildFixture();
    installFixture(fixture);

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).resolves.toMatchObject({
      protocol: "refmd.verified-signed-pq-wrap-operation",
      sequence: fixture.record.operation_checkpoint.checkpoint_sequence,
      wrapEventHash: fixture.record.event.wrap_event_hash,
      recordCommitmentHash: blake3Base64Url(
        canonicalizeStrictBytes(fixture.record as unknown as StrictJsonValue),
      ),
    });
  });

  it("retains only ancestry used by the verified proof", async () => {
    const fixture = buildFixture();
    const unrelated = successorCheckpoint(fixture.checkpoint, HASH_B);
    installFixture(fixture);
    fixture.container.workspace_key_directory_checkpoint_ancestry = [fixture.checkpoint, unrelated];

    await verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container);

    expect(pins.remember).toHaveBeenCalledWith(
      expect.objectContaining({
        checkpointEnvelope: fixture.checkpoint,
        checkpointAncestry: [],
        eventAncestry: [fixture.event],
      }),
    );
  });

  it("accepts a retained verified operation checkpoint ancestor", async () => {
    const fixture = buildFixture();
    const successor = successorCheckpoint(fixture.checkpoint);
    installFixture(fixture, successor);

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).resolves.toMatchObject({ checkpointHash: checkpointHash(fixture.checkpoint) });
  });

  it("advances a lower current pin with supplied proof before verification", async () => {
    const fixture = buildFixture();
    const predecessor = predecessorCheckpoint(fixture);
    verifiedCheckpoints = [predecessor];
    verifiedEvents = [];
    currentPin = pinFor(fixture.workspaceId, predecessor);
    fixture.container.workspace_key_directory_checkpoint_ancestry = [
      predecessor,
      fixture.checkpoint,
    ];
    pins.advance.mockImplementation(async () => {
      verifiedCheckpoints = [predecessor, fixture.checkpoint];
      verifiedEvents = [fixture.event];
      currentPin = pinFor(fixture.workspaceId, fixture.checkpoint);
    });

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).resolves.toBeDefined();
    expect(pins.advance).toHaveBeenCalledOnce();
  });

  it("rejects an unknown older checkpoint", async () => {
    const fixture = buildFixture();
    const successor = successorCheckpoint(fixture.checkpoint);
    const current = successorCheckpoint(successor);
    installFixture(fixture, current);
    verifiedCheckpoints = [current];

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).rejects.toThrow("signed_pq_wrap_checkpoint_lineage_missing");
  });

  it("rejects a same-sequence checkpoint fork", async () => {
    const fixture = buildFixture();
    installFixture(fixture);
    currentPin = {
      ...currentPin,
      checkpointHash: HASH_A === checkpointHash(fixture.checkpoint) ? HASH_B : HASH_A,
    };

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).rejects.toThrow("signed_pq_wrap_operation_checkpoint_fork");
  });

  it("rejects a fork in retained checkpoint ancestry", async () => {
    const fixture = buildFixture();
    const successor = successorCheckpoint(fixture.checkpoint, HASH_A);
    installFixture(fixture, successor);

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).rejects.toThrow("signed_pq_wrap_checkpoint_lineage_fork");
  });

  it("rejects a missing or forked wrap event", async () => {
    const fixture = buildFixture();
    installFixture(fixture);
    verifiedEvents = [];
    fixture.container.workspace_key_directory_event_ancestry = [];
    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).rejects.toThrow("signed_pq_wrap_event_missing");

    verifiedEvents = [fixture.event];
    fixture.event.payload = { ...fixture.event.payload, body: { forked: true } };
    fixture.container.workspace_key_directory_event_ancestry = [fixture.event];
    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).rejects.toThrow("signed_pq_wrap_event_missing");
  });

  it("rejects wrap event body and body-hash mismatches", async () => {
    const fixture = buildFixture();
    installFixture(fixture);
    const expectedBody = signedPqWrapEventBody(fixture.record) as Record<string, unknown>;
    fixture.event.payload = {
      ...fixture.event.payload,
      body: { ...expectedBody, purpose: "forked" },
    };
    fixture.record.event.wrap_event_hash = eventHash(fixture.event);
    verifiedEvents = [fixture.event];

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).rejects.toThrow("signed_pq_wrap_event_body_mismatch");
  });

  it("rejects a wrap event outside the operation covered head", async () => {
    const fixture = buildFixture();
    installFixture(fixture);
    fixture.record.operation_checkpoint.covered_event_head_sequence =
      fixture.record.event.wrap_event_sequence - 1;
    fixture.record.operation_checkpoint.covered_event_head_hash = HASH_A;
    fixture.checkpoint.payload = {
      ...fixture.checkpoint.payload,
      covered_event_head: {
        head_sequence: fixture.record.event.wrap_event_sequence - 1,
        head_hash: HASH_A,
      },
    };
    fixture.record.operation_checkpoint.checkpoint_hash = checkpointHash(fixture.checkpoint);
    verifiedCheckpoints = [fixture.checkpoint];
    currentPin = pinFor(fixture.workspaceId, fixture.checkpoint);

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).rejects.toThrow("signed_pq_wrap_event_not_covered");
  });

  it("rejects when forward proof does not advance the current pin", async () => {
    const fixture = buildFixture();
    const predecessor = predecessorCheckpoint(fixture);
    verifiedCheckpoints = [predecessor, fixture.checkpoint];
    verifiedEvents = [fixture.event];
    currentPin = pinFor(fixture.workspaceId, predecessor);
    pins.advance.mockResolvedValue(undefined);

    await expect(
      verifyWorkspaceSignedPqWrapOperation(fixture.workspaceId, fixture.container),
    ).rejects.toThrow("signed_pq_wrap_operation_checkpoint_ahead_of_pin");
  });
});

function buildFixture(): Fixture {
  const workspaceId = crypto.randomUUID();
  const senderDeviceId = crypto.randomUUID();
  const recipientDeviceId = crypto.randomUUID();
  const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
  const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
    "device",
    recipientDeviceId,
  );
  const initial = createSignedPqWrap({
    purpose: "workspace_device_kek_wrap",
    plaintext: crypto.getRandomValues(new Uint8Array(32)),
    recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
    senderSigningPrivateKeyMaterial: senderSigning,
    senderUserId: crypto.randomUUID(),
    senderDeviceId,
    resource: {
      workspace_id: workspaceId,
      target_user_id: crypto.randomUUID(),
      target_device_id: recipientDeviceId,
      kek_version: 1,
    },
    eventScope: { scope_kind: "workspace", scope_id: workspaceId },
    operationCheckpoint: {
      sequence: 1,
      checkpointHash: HASH_A,
      coveredHeadSequence: 1,
      coveredHeadHash: HASH_B,
    },
  });
  const event = signed(
    wrapIssuedKeyDirectoryEventFromRecord({
      scopeKind: "workspace",
      scopeId: workspaceId,
      coveredHead: { head_sequence: 1, head_hash: HASH_B },
      wrapRecord: initial,
    }),
  );
  const checkpoint = signed(
    keyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: workspaceId,
      sequence: 2,
      issuedAt: new Date(0).toISOString(),
      previousCheckpointHash: HASH_A,
      coveredEventHead: eventHead(event.payload),
      identityKeys: [],
      deviceKeys: [],
      shareParticipantKeys: [],
      revokedKeyIds: [],
    }),
  );
  const record = finalizeSignedPqWrapOperationCheckpoint({
    record: initial,
    operationCheckpoint: {
      sequence: 2,
      checkpointHash: checkpointHash(checkpoint),
      coveredHeadSequence: initial.event.wrap_event_sequence,
      coveredHeadHash: initial.event.wrap_event_hash,
    },
    senderSigningPrivateKeyMaterial: senderSigning,
  });
  return {
    workspaceId,
    record,
    event,
    checkpoint,
    container: {
      ...record,
      workspace_key_directory_checkpoint: checkpoint,
      workspace_key_directory_checkpoint_ancestry: [checkpoint],
      workspace_key_directory_event_ancestry: [event],
    },
  };
}

function installFixture(fixture: Fixture, current = fixture.checkpoint): void {
  verifiedCheckpoints =
    current === fixture.checkpoint ? [fixture.checkpoint] : [fixture.checkpoint, current];
  verifiedEvents = [fixture.event];
  currentPin = pinFor(fixture.workspaceId, current);
}

function successorCheckpoint(
  checkpoint: SignedKeyDirectoryEnvelope,
  previousCheckpointHash = checkpointHash(checkpoint),
): SignedKeyDirectoryEnvelope {
  return signed(
    keyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: checkpoint.payload.scope_id as string,
      sequence: (checkpoint.payload.sequence as number) + 1,
      issuedAt: new Date(1).toISOString(),
      previousCheckpointHash,
      coveredEventHead: checkpoint.payload.covered_event_head as Record<string, unknown>,
      identityKeys: [],
      deviceKeys: [],
      shareParticipantKeys: [],
      revokedKeyIds: [],
    }),
  );
}

function predecessorCheckpoint(fixture: Fixture): SignedKeyDirectoryEnvelope {
  return signed(
    keyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: fixture.workspaceId,
      sequence: 1,
      issuedAt: new Date(0).toISOString(),
      coveredEventHead: { head_sequence: 1, head_hash: HASH_B },
      identityKeys: [],
      deviceKeys: [],
      shareParticipantKeys: [],
      revokedKeyIds: [],
    }),
  );
}

function pinFor(workspaceId: string, checkpoint: SignedKeyDirectoryEnvelope): KeyDirectoryPin {
  const head = checkpoint.payload.covered_event_head as Record<string, unknown>;
  return {
    pinKey: `workspace:${workspaceId}`,
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointSequence: checkpoint.payload.sequence as number,
    checkpointHash: checkpointHash(checkpoint),
    eventHeadSequence: head.head_sequence as number,
    eventHeadHash: head.head_hash as string,
    suitePolicyVersion: 1,
    minSuiteRank: 1,
    allowedSuiteIdsHash: HASH_A,
    observedAt: 0,
  };
}

function signed(payload: Record<string, unknown>): SignedKeyDirectoryEnvelope {
  return {
    payload,
    signatures: [{ signer: {}, signature: {} as never }],
  };
}
