import { beforeEach, describe, expect, it, vi } from "vitest";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { currentSuitePolicy } from "@/shared/lib/crypto/suite";
import {
  buildKeyDirectoryCheckpointTranscript,
  buildKeyDirectoryEventTranscript,
  computeSigningKeyId,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
  signKeyDirectoryCheckpointSignature,
  signKeyDirectoryEventSignature,
  type HybridSigningPrivateKeyMaterial,
} from "@/shared/lib/crypto/signature";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  installTransferredKeyDirectoryCheckpoint,
  type KeyDirectoryPin,
} from "./pins";

const pinStore = new Map<string, KeyDirectoryPin>();
const WORKSPACE_TRANSFER_ID = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_PROOF_ID = "22222222-2222-4222-8222-222222222222";
const USER_ID = "33333333-3333-4333-8333-333333333333";
const DEVICE_ID = "44444444-4444-4444-8444-444444444444";

vi.mock("@/shared/lib/storage/idb", () => ({
  openIdb: vi.fn(async () => ({})),
  idbGet: vi.fn(async (_db: unknown, _storeName: string, key: string) => pinStore.get(key)),
  idbConditionalPut: vi.fn(
    async (
      _db: unknown,
      _storeName: string,
      key: string,
      value: KeyDirectoryPin,
      predicate: (existing: KeyDirectoryPin | undefined) => boolean,
    ) => {
      const existing = pinStore.get(key);
      if (!predicate(existing)) return false;
      pinStore.set(key, value);
      return true;
    },
  ),
}));

vi.mock("@/shared/lib/crypto/worker/client", async () => {
  const signature = await vi.importActual<typeof import("@/shared/lib/crypto/signature")>(
    "@/shared/lib/crypto/signature",
  );

  return {
    getCryptoWorker: () => ({
      verifyKeyDirectoryCheckpointSignature: vi.fn(async (params: Record<string, unknown>) =>
        signature.verifyKeyDirectoryCheckpointSignature({
          publicKeyMaterial: params.publicKeyMaterial as HybridSigningPublicKeyMaterial,
          signature: params.signature as never,
          transcript: signature.buildKeyDirectoryCheckpointTranscript({
            variant: params.variant as never,
            ownerKind: (params.publicKeyMaterial as HybridSigningPublicKeyMaterial).owner_kind,
            ownerId: (params.publicKeyMaterial as HybridSigningPublicKeyMaterial).owner_id,
            checkpointPayload: params.checkpointPayload as StrictJsonValue,
            signer: params.signer as StrictJsonValue,
          }),
        }),
      ),
      verifyKeyDirectoryEventSignature: vi.fn(async (params: Record<string, unknown>) =>
        signature.verifyKeyDirectoryEventSignature({
          publicKeyMaterial: params.publicKeyMaterial as HybridSigningPublicKeyMaterial,
          signature: params.signature as never,
          transcript: signature.buildKeyDirectoryEventTranscript({
            eventType: params.eventType as never,
            ownerKind: (params.publicKeyMaterial as HybridSigningPublicKeyMaterial).owner_kind,
            ownerId: (params.publicKeyMaterial as HybridSigningPublicKeyMaterial).owner_id,
            eventPayload: params.eventPayload as StrictJsonValue,
          }),
        }),
      ),
    }),
  };
});

describe("key-directory anti-rollback pins", () => {
  beforeEach(() => {
    pinStore.clear();
  });

  it("rejects transferred checkpoint conflicts instead of replacing an existing pin", async () => {
    const chain = keyDirectoryChain("workspace", WORKSPACE_TRANSFER_ID, 2);

    await installTransferredKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: WORKSPACE_TRANSFER_ID,
      checkpointEnvelope: chain[0]!.checkpoint,
    });

    await expect(
      installTransferredKeyDirectoryCheckpoint({
        scopeKind: "workspace",
        scopeId: WORKSPACE_TRANSFER_ID,
        checkpointEnvelope: chain[1]!.checkpoint,
      }),
    ).rejects.toThrow("key_directory_pin_conflict");

    await expect(getKeyDirectoryPin("workspace", WORKSPACE_TRANSFER_ID)).resolves.toMatchObject({
      checkpointSequence: 1,
      checkpointHash: hashKeyDirectoryCheckpointEnvelope(chain[0]!.checkpoint),
    });
  });

  it("advances pins only with ancestry anchored at the local pin", async () => {
    const chain = keyDirectoryChain("workspace", WORKSPACE_PROOF_ID, 3);

    await installTransferredKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: WORKSPACE_PROOF_ID,
      checkpointEnvelope: chain[0]!.checkpoint,
    });

    await advanceKeyDirectoryPinWithProof({
      scopeKind: "workspace",
      scopeId: WORKSPACE_PROOF_ID,
      checkpointEnvelope: chain[1]!.checkpoint,
      checkpointAncestry: [chain[0]!.checkpoint],
      eventAncestry: [chain[1]!.event],
    });

    await expect(getKeyDirectoryPin("workspace", WORKSPACE_PROOF_ID)).resolves.toMatchObject({
      checkpointSequence: 2,
      checkpointHash: hashKeyDirectoryCheckpointEnvelope(chain[1]!.checkpoint),
    });

    await expect(
      advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: WORKSPACE_PROOF_ID,
        checkpointEnvelope: chain[2]!.checkpoint,
        checkpointAncestry: [chain[0]!.checkpoint, chain[1]!.checkpoint],
        eventAncestry: [chain[2]!.event],
      }),
    ).rejects.toThrow("key_directory_checkpoint_anchor_mismatch");

    await advanceKeyDirectoryPinWithProof({
      scopeKind: "workspace",
      scopeId: WORKSPACE_PROOF_ID,
      checkpointEnvelope: chain[2]!.checkpoint,
      checkpointAncestry: [chain[1]!.checkpoint],
      eventAncestry: [chain[2]!.event],
    });

    await expect(
      advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: WORKSPACE_PROOF_ID,
        checkpointEnvelope: chain[1]!.checkpoint,
        checkpointAncestry: [chain[1]!.checkpoint],
        eventAncestry: [chain[1]!.event],
      }),
    ).rejects.toThrow("key_directory_checkpoint_rollback");
  });
});

function keyDirectoryChain(scopeKind: "user" | "workspace", scopeId: string, length: number) {
  const policy = currentSuitePolicy();
  const ownerKind = scopeKind === "workspace" ? "device" : "identity";
  const ownerId = scopeKind === "workspace" ? DEVICE_ID : USER_ID;
  const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial(ownerKind, ownerId);
  const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
  const signingKeyId = computeSigningKeyId(publicKeyMaterial);
  const signerBase = {
    signer_kind: ownerKind,
    user_id: USER_ID,
    device_id: scopeKind === "workspace" ? DEVICE_ID : undefined,
    signing_key_id: signingKeyId,
  };
  const keyEntry = {
    key_id: signingKeyId,
    key_material: publicKeyMaterial,
    valid_from: {
      scope_kind: scopeKind,
      scope_id: scopeId,
      event_sequence: 1,
      event_hash: "A".repeat(43),
    },
  };
  const entries =
    scopeKind === "workspace"
      ? { identity_keys: [], device_keys: [keyEntry] }
      : { identity_keys: [keyEntry], device_keys: [] };

  const result: Array<{ event: Record<string, unknown>; checkpoint: Record<string, unknown> }> = [];
  let previousEventHash: string | null = null;
  let previousCheckpointHash: string | null = null;

  for (let sequence = 1; sequence <= length; sequence += 1) {
    const actor = compactRecord({
      ...signerBase,
      ...(sequence === 1
        ? {}
        : {
            key_scope_kind: scopeKind,
            key_scope_id: scopeId,
            key_checkpoint_sequence: sequence - 1,
            key_checkpoint_hash: previousCheckpointHash,
          }),
    });
    const eventPayload: Record<string, unknown> = {
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: scopeKind,
      scope_id: scopeId,
      sequence,
      event_type: "suite_policy_changed",
      actor,
      body: {
        suite_policy_version: policy.suite_policy_version,
        min_suite_rank: policy.min_suite_rank,
        allowed_suite_ids: policy.allowed_suite_ids,
      },
    };
    if (previousEventHash) eventPayload.previous_event_hash = previousEventHash;

    const event =
      sequence === 1
        ? { payload: eventPayload, signatures: [] }
        : signedKeyDirectoryEventEnvelope(eventPayload, actor, privateKeyMaterial);
    const eventHeadHash = hashPayload(eventPayload);
    const checkpointSigner = compactRecord({
      ...signerBase,
      ...(sequence === 1
        ? {}
        : {
            authorizing_checkpoint_sequence: sequence - 1,
            authorizing_checkpoint_hash: previousCheckpointHash,
          }),
    });
    const checkpointPayload: Record<string, unknown> = {
      protocol: "refmd.key-directory-checkpoint",
      version: 1,
      scope_kind: scopeKind,
      scope_id: scopeId,
      sequence,
      issued_at: `2026-05-11T00:00:0${sequence}.000000Z`,
      covered_event_head: {
        head_sequence: sequence,
        head_hash: eventHeadHash,
      },
      suite_policy_version: policy.suite_policy_version,
      min_suite_rank: policy.min_suite_rank,
      allowed_suite_ids: policy.allowed_suite_ids,
      share_participant_keys: [],
      revoked_key_ids: [],
      ...entries,
    };
    if (previousCheckpointHash) checkpointPayload.previous_checkpoint_hash = previousCheckpointHash;

    const checkpoint = signedKeyDirectoryCheckpointEnvelope(
      checkpointPayload,
      checkpointSigner,
      privateKeyMaterial,
    );
    result.push({ event, checkpoint });
    previousEventHash = eventHeadHash;
    previousCheckpointHash = hashPayload(checkpointPayload);
  }

  return result;
}

function signedKeyDirectoryEventEnvelope(
  payload: Record<string, unknown>,
  signer: Record<string, unknown>,
  privateKeyMaterial: HybridSigningPrivateKeyMaterial,
) {
  return {
    payload,
    signatures: [
      {
        signer: compactRecord(signer),
        signature: signKeyDirectoryEventSignature({
          privateKeyMaterial,
          transcript: buildKeyDirectoryEventTranscript({
            eventType: payload.event_type as never,
            ownerKind: privateKeyMaterial.owner_kind,
            ownerId: privateKeyMaterial.owner_id,
            eventPayload: payload as StrictJsonValue,
          }),
        }),
      },
    ],
  };
}

function signedKeyDirectoryCheckpointEnvelope(
  payload: Record<string, unknown>,
  signer: Record<string, unknown>,
  privateKeyMaterial: HybridSigningPrivateKeyMaterial,
) {
  return {
    payload,
    signatures: [
      {
        signer: compactRecord(signer),
        signature: signKeyDirectoryCheckpointSignature({
          privateKeyMaterial,
          transcript: buildKeyDirectoryCheckpointTranscript({
            variant: checkpointVariant(payload),
            ownerKind: privateKeyMaterial.owner_kind,
            ownerId: privateKeyMaterial.owner_id,
            checkpointPayload: payload as StrictJsonValue,
            signer: signer as StrictJsonValue,
          }),
        }),
      },
    ],
  };
}

function checkpointVariant(payload: Record<string, unknown>) {
  if (payload.scope_kind === "user" && payload.sequence === 1) return "identity_initial";
  if (payload.scope_kind === "user") return "identity_active";
  if (payload.scope_kind === "workspace" && payload.sequence === 1) return "workspace_initial";
  return "workspace_authorized";
}

function hashPayload(payload: Record<string, unknown>): string {
  return blake3Base64Url(canonicalizeStrictBytes(payload as StrictJsonValue));
}

function compactRecord(record: Record<string, unknown>) {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}
