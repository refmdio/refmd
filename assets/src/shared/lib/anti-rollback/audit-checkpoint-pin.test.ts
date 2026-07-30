import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { AuditCheckpointPin } from "./audit-checkpoint-pin";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  auditCheckpointHash,
  buildAuditCheckpointTranscript,
  computeSigningKeyId,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
  signAuditCheckpointSignature,
  type HybridSigningPrivateKeyMaterial,
  type HybridSigningPublicKeyMaterial,
} from "@/shared/lib/crypto/signature";
import { checkpointHash, eventHash } from "./key-directory-pin/primitives";
import { idbAtomicConditionalPuts } from "@/shared/lib/storage/idb";

const USER_ID = "00000000-0000-4000-8000-000000000001";
const pins = new Map<string, AuditCheckpointPin>();
const verifiedAuthorityCheckpoints: Array<{
  payload: Record<string, unknown>;
  signatures: Record<string, unknown>[];
}> = [];
const verifiedAuthorityEvents: Array<{
  payload: Record<string, unknown>;
  signatures: Record<string, unknown>[];
}> = [];

let privateKeyMaterial: HybridSigningPrivateKeyMaterial;
let publicKeyMaterial: HybridSigningPublicKeyMaterial;

vi.mock("./key-directory-pin/pins", () => ({
  lookupVerifiedKeyDirectoryCheckpointBodies: () => verifiedAuthorityCheckpoints,
  lookupVerifiedKeyDirectoryEventBodies: () => verifiedAuthorityEvents,
}));
vi.mock("@/shared/lib/storage/idb", () => ({
  openIdb: vi.fn(async () => ({ close: vi.fn() })),
  idbGet: vi.fn(async (_db: unknown, _store: string, key: string | string[]) =>
    pins.get(Array.isArray(key) ? key.join(":") : key),
  ),
  idbConditionalPut: vi.fn(
    async (
      _db: unknown,
      _store: string,
      key: string | string[],
      value: AuditCheckpointPin,
      predicate: (existing: AuditCheckpointPin | undefined) => boolean,
    ) => {
      const normalizedKey = Array.isArray(key) ? key.join(":") : key;
      const existing = pins.get(normalizedKey);
      if (!predicate(existing)) return false;
      pins.set(normalizedKey, value);
      return true;
    },
  ),
  idbConditionalPutWithRequiredRecord: vi.fn(
    async (params: {
      targetKey: string[];
      targetValue: AuditCheckpointPin;
      shouldWrite: (existing: AuditCheckpointPin | undefined) => boolean;
    }) => {
      const key = params.targetKey.join(":");
      const existing = pins.get(key);
      if (!params.shouldWrite(existing)) return false;
      pins.set(key, params.targetValue);
      return true;
    },
  ),
  idbAtomicConditionalPuts: vi.fn(async () => undefined),
}));

describe("signed audit checkpoint pins", () => {
  beforeEach(() => {
    pins.clear();
    verifiedAuthorityCheckpoints.length = 0;
    verifiedAuthorityEvents.length = 0;
    privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("identity", USER_ID);
    publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    verifiedAuthorityCheckpoints.push(authorityCheckpoint(publicKeyMaterial));
    verifiedAuthorityEvents.push(...userGenesisAuthorityEvents());
    vi.mocked(idbAtomicConditionalPuts).mockClear();
  });

  it("verifies the hybrid signature and pins the signed checkpoint hash", async () => {
    const { getAuditCheckpointPin, verifyAndPinAuditCheckpoint } =
      await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(1);
    await verifyAndPinAuditCheckpoint(candidate, genesisOptions(candidate));

    await expect(getAuditCheckpointPin("user", USER_ID)).resolves.toMatchObject({
      checkpoint_sequence: 1,
      checkpoint_hash: candidate.signed_checkpoint.checkpoint_hash,
      event_head_hash: candidate.signed_checkpoint.payload.event_hash,
    });
  });

  it("rejects user genesis audit actor and candidate-device subject substitution", async () => {
    const { verifyAuditCheckpointCandidate } = await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(1);
    const event = candidate.ancestry[0]!;
    const body = event.event_body as {
      actor: { kind: string; user_id: string };
      subject_id: string;
    };
    body.actor.kind = "device";
    body.subject_id = USER_ID;
    const preimage = { ...event };
    delete preimage.event_hash;
    event.event_hash = blake3Base64Url(canonicalizeStrictBytes(preimage as StrictJsonValue));
    candidate.signed_checkpoint.payload.event_hash = event.event_hash as string;
    candidate.current_event_head.event_hash = event.event_hash as string;
    resign(candidate);

    await expect(
      verifyAuditCheckpointCandidate(candidate, genesisOptions(candidate)),
    ).rejects.toThrow("audit_checkpoint_authority_unverified");
  });

  it("rejects component tampering before pin persistence", async () => {
    const { getAuditCheckpointPin, verifyAndPinAuditCheckpoint } =
      await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(1);
    candidate.signed_checkpoint.signature.ed25519 = zeroSignature(64);

    await expect(verifyAndPinAuditCheckpoint(candidate, genesisOptions(candidate))).rejects.toThrow(
      "audit_checkpoint_signature_invalid",
    );
    await expect(getAuditCheckpointPin("user", USER_ID)).resolves.toBeNull();
  });

  it("rejects the obsolete audit-chain wrapper", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(1);
    candidate.ancestry[0]!.protocol = "refmd.security-audit-chain";

    await expect(verifyAndPinAuditCheckpoint(candidate, genesisOptions(candidate))).rejects.toThrow(
      "audit_checkpoint_ancestry_invalid",
    );
  });

  it("rejects rollback, same-sequence forks, and previous-checkpoint substitution", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const first = signedCheckpointResponse(1);
    await verifyAndPinAuditCheckpoint(first, genesisOptions(first));

    const fork = signedCheckpointResponse(1, undefined, "user.identity.key_added");
    await expect(verifyAndPinAuditCheckpoint(fork)).rejects.toThrow(
      "audit_checkpoint_rollback_or_fork",
    );

    const second = signedCheckpointResponse(2, {
      sequence: 1,
      checkpointHash: first.signed_checkpoint.checkpoint_hash,
      eventHash: first.signed_checkpoint.payload.event_hash as string,
    });
    second.signed_checkpoint.payload.previous_signed_checkpoint_hash = hash("wrong-previous");
    resign(second);
    await expect(verifyAndPinAuditCheckpoint(second)).rejects.toThrow(
      "audit_checkpoint_previous_mismatch",
    );
  });

  it("rejects a high-risk event in the unsigned tail", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(1);
    const tail = nextAuditEvent(
      2,
      candidate.signed_checkpoint.payload.event_hash as string,
      "user.device.approved",
    );
    candidate.unsigned_tail = [tail];
    candidate.current_event_head = { sequence: 2, event_hash: tail.event_hash as string };

    await expect(verifyAndPinAuditCheckpoint(candidate, genesisOptions(candidate))).rejects.toThrow(
      "audit_checkpoint_high_risk_unsigned_tail",
    );
  });

  it("rejects a high-risk runtime event in the unsigned tail", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(1);
    const tail = nextAuditEvent(
      2,
      candidate.signed_checkpoint.payload.event_hash as string,
      "plugin.network.requested",
    );
    candidate.unsigned_tail = [tail];
    candidate.current_event_head = { sequence: 2, event_hash: tail.event_hash as string };

    await expect(verifyAndPinAuditCheckpoint(candidate, genesisOptions(candidate))).rejects.toThrow(
      "audit_checkpoint_high_risk_unsigned_tail",
    );
  });

  it("rejects unknown unsigned-tail event types", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(1);
    const tail = nextAuditEvent(
      2,
      candidate.signed_checkpoint.payload.event_hash as string,
      "plugin.ui.unknown",
    );
    candidate.unsigned_tail = [tail];
    candidate.current_event_head = { sequence: 2, event_hash: tail.event_hash as string };

    await expect(verifyAndPinAuditCheckpoint(candidate, genesisOptions(candidate))).rejects.toThrow(
      "unknown_security_audit_event",
    );
  });

  it("accepts only an exact closed low-risk runtime tail", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(1);
    const tail = nextAuditEvent(
      2,
      candidate.signed_checkpoint.payload.event_hash as string,
      "plugin.ui.registration.rejected",
    );
    candidate.unsigned_tail = [tail];
    candidate.current_event_head = { sequence: 2, event_hash: tail.event_hash as string };

    await expect(
      verifyAndPinAuditCheckpoint(candidate, genesisOptions(candidate)),
    ).resolves.toMatchObject({
      checkpoint_sequence: 1,
      event_head_sequence: 1,
    });

    const invalid = signedCheckpointResponse(1);
    const invalidTail = nextAuditEvent(
      2,
      invalid.signed_checkpoint.payload.event_hash as string,
      "plugin.ui.registration.rejected",
    );
    (invalidTail.event_body as { action: { result: string } }).action.result = "completed";
    const preimage = { ...invalidTail };
    delete preimage.event_hash;
    invalidTail.event_hash = blake3Base64Url(canonicalizeStrictBytes(preimage as StrictJsonValue));
    invalid.unsigned_tail = [invalidTail];
    invalid.current_event_head = { sequence: 2, event_hash: invalidTail.event_hash as string };
    await expect(verifyAndPinAuditCheckpoint(invalid, genesisOptions(invalid))).rejects.toThrow(
      "unknown_security_audit_event",
    );
  });

  it("rebuilds transferred trust evidence and writes all security pins atomically", async () => {
    const { buildAuditCheckpointPinSet, installTransferredSecurityPinSet } =
      await import("./audit-checkpoint-pin");
    const userPin = transferredUserPin(USER_ID);
    const workspacePin = transferredWorkspacePin("00000000-0000-4000-8000-000000000011");
    const built = buildAuditCheckpointPinSet({
      trustTransferId: "00000000-0000-4000-8000-000000000021",
      sourceDeviceId: "00000000-0000-4000-8000-000000000022",
      targetDeviceId: "00000000-0000-4000-8000-000000000023",
      ownerUserId: USER_ID,
      pins: [workspacePin, userPin],
    });
    await installTransferredSecurityPinSet({
      pinSet: built.pinSet,
      pinSetHash: built.pinSetHash,
      verifiedAuditPins: built.pinSet.pins,
      keyDirectoryPins: [
        keyDirectoryPin("user", USER_ID),
        keyDirectoryPin("workspace", workspacePin.chain_scope_id),
      ],
      authorizationCheckpoints: [
        {
          scopeKind: "user",
          scopeId: USER_ID,
          sequence: userPin.authorization_checkpoint_sequence,
          hash: userPin.authorization_checkpoint_hash,
        },
        {
          scopeKind: "workspace",
          scopeId: workspacePin.chain_scope_id,
          sequence: workspacePin.authorization_checkpoint_sequence,
          hash: workspacePin.authorization_checkpoint_hash,
        },
      ],
    });

    const writes = vi.mocked(idbAtomicConditionalPuts).mock.calls[0]?.[1] ?? [];
    expect(writes).toHaveLength(4);
    expect(
      writes
        .filter((write) => write.storeName === "audit-checkpoint-pins")
        .map((write) => write.value),
    ).toEqual([
      expect.objectContaining({ trust_state: "anchored", anchor_evidence_hash: built.pinSetHash }),
      expect.objectContaining({ trust_state: "anchored", anchor_evidence_hash: built.pinSetHash }),
    ]);
  });

  it("rejects a transferred audit pin without its authorization checkpoint proof", async () => {
    const { buildAuditCheckpointPinSet, installTransferredSecurityPinSet } =
      await import("./audit-checkpoint-pin");
    const userPin = transferredUserPin(USER_ID);
    const built = buildAuditCheckpointPinSet({
      trustTransferId: "00000000-0000-4000-8000-000000000021",
      sourceDeviceId: "00000000-0000-4000-8000-000000000022",
      targetDeviceId: "00000000-0000-4000-8000-000000000023",
      ownerUserId: USER_ID,
      pins: [userPin],
    });

    await expect(
      installTransferredSecurityPinSet({
        pinSet: built.pinSet,
        pinSetHash: built.pinSetHash,
        verifiedAuditPins: built.pinSet.pins,
        keyDirectoryPins: [keyDirectoryPin("user", USER_ID)],
        authorizationCheckpoints: [],
      }),
    ).rejects.toThrow("audit_checkpoint_authorization_proof_missing");
    expect(idbAtomicConditionalPuts).not.toHaveBeenCalled();
  });

  it("rejects workspace admin authority lost before the referenced checkpoint", async () => {
    const { verifyAuditCheckpointCandidate } = await import("./audit-checkpoint-pin");
    const workspaceId = "00000000-0000-4000-8000-000000000031";
    const deviceId = "00000000-0000-4000-8000-000000000032";
    privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", deviceId);
    publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    verifiedAuthorityCheckpoints.splice(
      0,
      verifiedAuthorityCheckpoints.length,
      workspaceAuthorityCheckpoint(workspaceId, publicKeyMaterial, 2),
    );
    verifiedAuthorityEvents.push(
      workspaceMemberEvent(workspaceId, USER_ID, 1, "member_added", {
        user_id: USER_ID,
        base_role: "owner",
      }),
      workspaceMemberEvent(workspaceId, USER_ID, 2, "member_role_changed", {
        user_id: USER_ID,
        base_role: "viewer",
        effective_permissions: ["document:read", "member:list"],
      }),
    );
    (
      verifiedAuthorityCheckpoints[0]!.payload.covered_event_head as Record<string, unknown>
    ).head_hash = eventHash(verifiedAuthorityEvents[1]! as never);

    await expect(
      verifyAuditCheckpointCandidate(
        signedWorkspaceCheckpointResponse(workspaceId, deviceId, publicKeyMaterial),
      ),
    ).rejects.toThrow("audit_checkpoint_authority_unverified");
  });

  it("accepts only the exact workspace genesis candidate authority", async () => {
    const { verifyAuditCheckpointCandidate } = await import("./audit-checkpoint-pin");
    const workspaceId = "00000000-0000-4000-8000-000000000041";
    const deviceId = "00000000-0000-4000-8000-000000000042";
    privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", deviceId);
    publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const events = workspaceGenesisAuthorityEvents(workspaceId, deviceId);
    const checkpoint = workspaceGenesisAuthorityCheckpoint(workspaceId, publicKeyMaterial, events);
    verifiedAuthorityCheckpoints.splice(0, verifiedAuthorityCheckpoints.length, checkpoint);
    verifiedAuthorityEvents.splice(0, verifiedAuthorityEvents.length, ...events);
    const candidate = signedWorkspaceGenesisCheckpointResponse(
      workspaceId,
      deviceId,
      publicKeyMaterial,
    );
    const options = workspaceGenesisOptions(candidate, checkpoint, workspaceId, deviceId);

    await expect(verifyAuditCheckpointCandidate(candidate, options)).resolves.toMatchObject({
      checkpoint_variant: "workspace_device",
      authorization_checkpoint_sequence: 0,
      authorization_checkpoint_hash: "GENESIS",
    });

    await expect(
      verifyAuditCheckpointCandidate(candidate, {
        genesisAuthority: {
          ...options.genesisAuthority,
          workspaceAuditCheckpointHash: hash("substituted-workspace-audit-checkpoint"),
        },
      }),
    ).rejects.toThrow("audit_checkpoint_authority_unverified");

    candidate.signed_checkpoint.payload.covered_event_type = "workspace.member.added";
    resignWorkspace(candidate, deviceId);
    await expect(verifyAuditCheckpointCandidate(candidate, options)).rejects.toThrow(
      "audit_checkpoint_authority_unverified",
    );
  });

  it("stores a verified Recovery bootstrap without claiming an external anchor", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const candidate = signedCheckpointResponse(2, {
      sequence: 1,
      checkpointHash: hash("previous-checkpoint"),
      eventHash: hash("previous-event"),
    });

    await expect(
      verifyAndPinAuditCheckpoint(candidate, {
        acquisition: "recovery",
        ...genesisOptions(candidate),
      }),
    ).resolves.toMatchObject({
      trust_state: "recovery_unanchored",
      anchor_evidence_hash: "NONE",
    });
    await expect(getStoredUserPin()).resolves.toMatchObject({
      trust_state: "recovery_unanchored",
      anchor_evidence_hash: "NONE",
    });
  });
});

async function getStoredUserPin() {
  const { getAuditCheckpointPin } = await import("./audit-checkpoint-pin");
  return getAuditCheckpointPin("user", USER_ID);
}

function signedCheckpointResponse(
  sequence: number,
  previous?: { sequence: number; checkpointHash: string; eventHash: string },
  finalType = "user.device.genesis_bootstrapped",
) {
  const events = auditEvents(sequence, finalType);
  const authority = verifiedAuthorityCheckpoints[0]!;
  const payload: Record<string, StrictJsonValue> = {
    protocol: "refmd.signed-audit-checkpoint",
    version: 1,
    chain_scope_kind: "user",
    chain_scope_id: USER_ID,
    sequence,
    event_hash: events.at(-1)!.event_hash as string,
    ...(sequence === 1
      ? {}
      : {
          previous_signed_checkpoint_sequence: previous!.sequence,
          previous_signed_checkpoint_hash: previous!.checkpointHash,
        }),
    signer_user_id: USER_ID,
    signing_key_id: computeSigningKeyId(publicKeyMaterial),
    authorization_checkpoint_scope_kind: "user",
    authorization_checkpoint_scope_id: USER_ID,
    authorization_checkpoint_sequence: sequence === 1 ? 0 : 1,
    authorization_checkpoint_hash: sequence === 1 ? "GENESIS" : checkpointHash(authority as never),
    covered_event_class: "authority",
    covered_event_type: finalType,
  };
  const transcript = buildAuditCheckpointTranscript({
    variant: "user_identity",
    ownerKind: "identity",
    ownerId: USER_ID,
    payload,
  });
  return {
    signed_checkpoint: {
      payload,
      signature: signAuditCheckpointSignature({ transcript, privateKeyMaterial }),
      checkpoint_hash: auditCheckpointHash(payload),
    },
    ancestry: events,
    current_event_head: { sequence, event_hash: payload.event_hash },
    unsigned_tail: [] as Record<string, unknown>[],
  };
}

function resign(candidate: ReturnType<typeof signedCheckpointResponse>): void {
  const payload = candidate.signed_checkpoint.payload;
  const transcript = buildAuditCheckpointTranscript({
    variant: "user_identity",
    ownerKind: "identity",
    ownerId: USER_ID,
    payload,
  });
  candidate.signed_checkpoint.signature = signAuditCheckpointSignature({
    transcript,
    privateKeyMaterial,
  });
  candidate.signed_checkpoint.checkpoint_hash = auditCheckpointHash(payload);
}

function auditEvents(sequence: number, finalType: string): Record<string, unknown>[] {
  const ancestry: Record<string, unknown>[] = [];
  let previousEventHash = "GENESIS";
  for (let current = 1; current <= sequence; current += 1) {
    const eventId = eventUuid(current);
    const eventType = current === sequence ? finalType : "user.account.genesis";
    const event: Record<string, StrictJsonValue> = {
      protocol: "refmd.audit.chain-event",
      version: 1,
      event_id: eventId,
      chain_scope_kind: "user",
      chain_scope_id: USER_ID,
      sequence: current,
      previous_event_hash: previousEventHash,
      event_type: eventType,
      event_body: auditEventBody(eventId, eventType),
    };
    const eventHash = blake3Base64Url(canonicalizeStrictBytes(event));
    ancestry.push({ ...event, event_hash: eventHash });
    previousEventHash = eventHash;
  }
  return ancestry;
}

function nextAuditEvent(
  sequence: number,
  previousEventHash: string,
  type: string,
): Record<string, unknown> {
  const eventId = eventUuid(sequence);
  const event: Record<string, StrictJsonValue> = {
    protocol: "refmd.audit.chain-event",
    version: 1,
    event_id: eventId,
    chain_scope_kind: "user",
    chain_scope_id: USER_ID,
    sequence,
    previous_event_hash: previousEventHash,
    event_type: type,
    event_body: auditEventBody(eventId, type),
  };
  return {
    ...event,
    event_hash: blake3Base64Url(canonicalizeStrictBytes(event as StrictJsonValue)),
  };
}

function auditEventBody(eventId: string, eventType: string): StrictJsonValue {
  if (
    eventType === "user.account.genesis" ||
    eventType === "user.device.genesis_bootstrapped" ||
    eventType === "user.identity.key_added" ||
    eventType === "user.device.approved"
  ) {
    return {
      protocol: "refmd.audit.high-risk-mutation",
      version: 1,
      event_type: eventType,
      mutation_id: "00000000-0000-4000-8000-000000000099",
      chain_scope_kind: "user",
      chain_scope_id: USER_ID,
      actor: { kind: "identity", user_id: USER_ID },
      subject_kind:
        eventType === "user.device.approved" || eventType === "user.device.genesis_bootstrapped"
          ? "user_device"
          : "user_account",
      subject_id:
        eventType === "user.device.genesis_bootstrapped"
          ? "00000000-0000-4000-8000-000000000002"
          : USER_ID,
      canonical_request_hash: hash(`request:${eventType}`),
      key_directory_effects_hash: hash(`effects:${eventType}`),
    };
  }
  const lowRiskRegistrationRejected = eventType === "plugin.ui.registration.rejected";
  return {
    protocol: "refmd.security-audit-event",
    version: 1,
    event_id: eventId,
    class: "security_runtime",
    type: eventType,
    actor: {
      user_id: USER_ID,
      device_id: null,
      session_id: null,
      principal_kind: "user",
      principal_id: USER_ID,
    },
    scope: { workspace_id: null, document_id: null, share_id: null },
    resource: {
      kind: lowRiskRegistrationRejected ? "plugin" : "credential",
      id: USER_ID,
      version_hash: null,
    },
    action: {
      operation: lowRiskRegistrationRejected ? "register" : eventType,
      result: lowRiskRegistrationRejected ? "denied" : "completed",
      reason_code: null,
    },
    sensitivity: {
      plaintext_scope_kind: "none",
      plaintext_bytes: 0,
      egress_bytes: 0,
      storage_bytes: 0,
    },
    correlation: {
      request_id: null,
      capability_id: null,
      execution_context_id: null,
      authority_event_ref: null,
    },
    created_at: "2026-07-15T00:00:00Z",
  };
}

function eventUuid(sequence: number): string {
  return `00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`;
}

function authorityCheckpoint(material: HybridSigningPublicKeyMaterial) {
  return {
    payload: {
      protocol: "refmd.key-directory-checkpoint",
      version: 1,
      scope_kind: "user",
      scope_id: USER_ID,
      sequence: 1,
      issued_at: "2026-07-15T00:00:00Z",
      suite_policy_version: 1,
      min_suite_rank: 1000,
      allowed_suite_ids: ["refmd-v2-hybrid-signature-ed25519-mldsa65"],
      required_components: ["ed25519", "mldsa65"],
      identity_keys: [
        {
          key_id: computeSigningKeyId(material),
          key_material: material,
          valid_from: {
            scope_kind: "user",
            scope_id: USER_ID,
            event_sequence: 1,
            event_hash: hash("key-event"),
          },
        },
      ],
      device_keys: [],
      share_participant_keys: [],
      revoked_key_ids: [],
      covered_event_head: {
        head_sequence: 4,
        head_hash: eventHash(userGenesisAuthorityEvents()[3] as never),
      },
    },
    signatures: [],
  };
}

function userGenesisAuthorityEvents() {
  return [
    userGenesisAuthorityEvent(1, "identity_key_added", { key_kind: "signing" }),
    userGenesisAuthorityEvent(2, "identity_key_added", { key_kind: "encryption" }),
    userGenesisAuthorityEvent(3, "suite_policy_changed", { suite_policy_version: 1 }),
    userGenesisAuthorityEvent(4, "device_key_added", {
      user_id: USER_ID,
      device_id: "00000000-0000-4000-8000-000000000002",
    }),
  ];
}

function userGenesisAuthorityEvent(
  sequence: number,
  eventType: string,
  body: Record<string, StrictJsonValue>,
) {
  return {
    payload: {
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "user",
      scope_id: USER_ID,
      sequence,
      event_type: eventType,
      actor: { signer_kind: "identity", user_id: USER_ID },
      body,
    },
    signatures: [],
  };
}

function genesisOptions(candidate: ReturnType<typeof signedCheckpointResponse>) {
  return {
    genesisAuthority: {
      userId: USER_ID,
      deviceId: "00000000-0000-4000-8000-000000000002",
      workspaceId: "00000000-0000-4000-8000-000000000003",
      userAuditCheckpointHash: candidate.signed_checkpoint.checkpoint_hash,
      workspaceAuditCheckpointHash: hash("workspace-audit-checkpoint"),
      userKeyDirectoryCheckpointHash: checkpointHash(verifiedAuthorityCheckpoints[0] as never),
      workspaceKeyDirectoryCheckpointHash: hash("workspace-key-directory-checkpoint"),
    },
  };
}

function workspaceAuthorityCheckpoint(
  workspaceId: string,
  material: HybridSigningPublicKeyMaterial,
  headSequence: number,
) {
  return {
    payload: {
      protocol: "refmd.key-directory-checkpoint",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: 1,
      issued_at: "2026-07-15T00:00:00Z",
      suite_policy_version: 1,
      min_suite_rank: 1000,
      allowed_suite_ids: ["refmd-v2-hybrid-signature-ed25519-mldsa65"],
      required_components: ["ed25519", "mldsa65"],
      identity_keys: [],
      device_keys: [
        {
          key_id: computeSigningKeyId(material),
          key_material: material,
          valid_from: {
            scope_kind: "workspace",
            scope_id: workspaceId,
            event_sequence: 1,
            event_hash: hash("workspace-key-event"),
          },
        },
      ],
      share_participant_keys: [],
      revoked_key_ids: [],
      covered_event_head: {
        head_sequence: headSequence,
        head_hash: hash(`workspace-event:${headSequence}`),
      },
    },
    signatures: [],
  };
}

function workspaceMemberEvent(
  workspaceId: string,
  userId: string,
  sequence: number,
  eventType: string,
  body: Record<string, StrictJsonValue>,
) {
  return {
    payload: {
      protocol: "refmd.signed-key-directory-event",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence,
      event_type: eventType,
      actor: { signer_kind: "device", user_id: userId },
      body,
    },
    signatures: [],
  };
}

function signedWorkspaceCheckpointResponse(
  workspaceId: string,
  deviceId: string,
  material: HybridSigningPublicKeyMaterial,
) {
  const eventId = "00000000-0000-4000-8000-000000000033";
  const eventType = "workspace.member.added";
  const event: Record<string, StrictJsonValue> = {
    protocol: "refmd.audit.chain-event",
    version: 1,
    event_id: eventId,
    chain_scope_kind: "workspace",
    chain_scope_id: workspaceId,
    sequence: 1,
    previous_event_hash: "GENESIS",
    event_type: eventType,
    event_body: {
      protocol: "refmd.audit.high-risk-mutation",
      version: 1,
      event_type: eventType,
      mutation_id: "00000000-0000-4000-8000-000000000034",
      chain_scope_kind: "workspace",
      chain_scope_id: workspaceId,
      actor: { kind: "device", user_id: USER_ID, device_id: deviceId },
      subject_kind: "workspace_member",
      subject_id: USER_ID,
      canonical_request_hash: hash("workspace-request"),
      key_directory_effects_hash: hash("workspace-effects"),
    },
  };
  const eventHash = blake3Base64Url(canonicalizeStrictBytes(event));
  const authority = verifiedAuthorityCheckpoints[0]!;
  const payload: Record<string, StrictJsonValue> = {
    protocol: "refmd.signed-audit-checkpoint",
    version: 1,
    chain_scope_kind: "workspace",
    chain_scope_id: workspaceId,
    sequence: 1,
    event_hash: eventHash,
    previous_signed_checkpoint_sequence: 1,
    previous_signed_checkpoint_hash: hash("previous-audit-checkpoint"),
    signer_user_id: USER_ID,
    signer_device_id: deviceId,
    signing_key_id: computeSigningKeyId(material),
    authorization_checkpoint_scope_kind: "workspace",
    authorization_checkpoint_scope_id: workspaceId,
    authorization_checkpoint_sequence: 1,
    authorization_checkpoint_hash: checkpointHash(authority as never),
    covered_event_class: "authority",
    covered_event_type: eventType,
  };
  const transcript = buildAuditCheckpointTranscript({
    variant: "workspace_device",
    ownerKind: "device",
    ownerId: deviceId,
    payload,
  });
  return {
    signed_checkpoint: {
      payload,
      signature: signAuditCheckpointSignature({ transcript, privateKeyMaterial }),
      checkpoint_hash: auditCheckpointHash(payload),
    },
    ancestry: [{ ...event, event_hash: eventHash }],
    current_event_head: { sequence: 1, event_hash: eventHash },
    unsigned_tail: [],
  };
}

function signedWorkspaceGenesisCheckpointResponse(
  workspaceId: string,
  deviceId: string,
  material: HybridSigningPublicKeyMaterial,
) {
  const eventId = "00000000-0000-4000-8000-000000000043";
  const event: Record<string, StrictJsonValue> = {
    protocol: "refmd.audit.chain-event",
    version: 1,
    event_id: eventId,
    chain_scope_kind: "workspace",
    chain_scope_id: workspaceId,
    sequence: 1,
    previous_event_hash: "GENESIS",
    event_type: "workspace.genesis",
    event_body: {
      protocol: "refmd.audit.high-risk-mutation",
      version: 1,
      event_type: "workspace.genesis",
      mutation_id: "00000000-0000-4000-8000-000000000044",
      chain_scope_kind: "workspace",
      chain_scope_id: workspaceId,
      actor: { kind: "device", user_id: USER_ID, device_id: deviceId },
      subject_kind: "workspace",
      subject_id: workspaceId,
      canonical_request_hash: hash("workspace-genesis-request"),
      key_directory_effects_hash: hash("workspace-genesis-effects"),
    },
  };
  const eventHashValue = blake3Base64Url(canonicalizeStrictBytes(event));
  const payload: Record<string, StrictJsonValue> = {
    protocol: "refmd.signed-audit-checkpoint",
    version: 1,
    chain_scope_kind: "workspace",
    chain_scope_id: workspaceId,
    sequence: 1,
    event_hash: eventHashValue,
    signer_user_id: USER_ID,
    signer_device_id: deviceId,
    signing_key_id: computeSigningKeyId(material),
    authorization_checkpoint_scope_kind: "workspace",
    authorization_checkpoint_scope_id: workspaceId,
    authorization_checkpoint_sequence: 0,
    authorization_checkpoint_hash: "GENESIS",
    covered_event_class: "authority",
    covered_event_type: "workspace.genesis",
  };
  const candidate = {
    signed_checkpoint: {
      payload,
      signature: {} as ReturnType<typeof signAuditCheckpointSignature>,
      checkpoint_hash: auditCheckpointHash(payload),
    },
    ancestry: [{ ...event, event_hash: eventHashValue }],
    current_event_head: { sequence: 1, event_hash: eventHashValue },
    unsigned_tail: [] as Record<string, unknown>[],
  };
  resignWorkspace(candidate, deviceId);
  return candidate;
}

function resignWorkspace(
  candidate: ReturnType<typeof signedWorkspaceGenesisCheckpointResponse>,
  deviceId: string,
): void {
  const payload = candidate.signed_checkpoint.payload;
  const transcript = buildAuditCheckpointTranscript({
    variant: "workspace_device",
    ownerKind: "device",
    ownerId: deviceId,
    payload,
  });
  candidate.signed_checkpoint.signature = signAuditCheckpointSignature({
    transcript,
    privateKeyMaterial,
  });
  candidate.signed_checkpoint.checkpoint_hash = auditCheckpointHash(payload);
}

function workspaceGenesisAuthorityEvents(workspaceId: string, deviceId: string) {
  const memberEnvelopeHash = hash("workspace-member-envelope");
  return [
    workspaceGenesisAuthorityEvent(workspaceId, deviceId, 1, "identity_key_added", {
      key_kind: "signing",
    }),
    workspaceGenesisAuthorityEvent(workspaceId, deviceId, 2, "identity_key_added", {
      key_kind: "encryption",
    }),
    workspaceGenesisAuthorityEvent(workspaceId, deviceId, 3, "device_key_added", {
      user_id: USER_ID,
      device_id: deviceId,
      signing_key_id: computeSigningKeyId(publicKeyMaterial),
    }),
    workspaceGenesisAuthorityEvent(workspaceId, deviceId, 4, "member_added", {
      workspace_id: workspaceId,
      user_id: USER_ID,
      base_role: "owner",
      workspace_member_envelope_hash: memberEnvelopeHash,
    }),
    workspaceGenesisAuthorityEvent(workspaceId, deviceId, 5, "suite_policy_changed", {
      suite_policy_version: 1,
    }),
    workspaceGenesisAuthorityEvent(workspaceId, deviceId, 6, "workspace_member_envelope_issued", {
      workspace_id: workspaceId,
      target_user_id: USER_ID,
      sender_device_id: deviceId,
      workspace_member_envelope_hash: memberEnvelopeHash,
    }),
  ];
}

function workspaceGenesisAuthorityEvent(
  workspaceId: string,
  deviceId: string,
  sequence: number,
  eventType: string,
  body: Record<string, StrictJsonValue>,
) {
  return {
    payload: {
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence,
      event_type: eventType,
      actor: { signer_kind: "device", user_id: USER_ID, device_id: deviceId },
      body,
    },
    signatures: [],
  };
}

function workspaceGenesisAuthorityCheckpoint(
  workspaceId: string,
  material: HybridSigningPublicKeyMaterial,
  events: ReturnType<typeof workspaceGenesisAuthorityEvents>,
) {
  return {
    payload: {
      protocol: "refmd.key-directory-checkpoint",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: 1,
      issued_at: "2026-07-15T00:00:00Z",
      suite_policy_version: 1,
      min_suite_rank: 1000,
      allowed_suite_ids: ["refmd-v2-hybrid-signature-ed25519-mldsa65"],
      required_components: ["ed25519", "mldsa65"],
      identity_keys: [],
      device_keys: [
        {
          key_id: computeSigningKeyId(material),
          key_material: material,
          valid_from: {
            scope_kind: "workspace",
            scope_id: workspaceId,
            event_sequence: 3,
            event_hash: eventHash(events[2] as never),
          },
        },
      ],
      share_participant_keys: [],
      revoked_key_ids: [],
      covered_event_head: { head_sequence: 6, head_hash: eventHash(events[5] as never) },
    },
    signatures: [],
  };
}

function workspaceGenesisOptions(
  candidate: ReturnType<typeof signedWorkspaceGenesisCheckpointResponse>,
  checkpoint: ReturnType<typeof workspaceGenesisAuthorityCheckpoint>,
  workspaceId: string,
  deviceId: string,
) {
  return {
    genesisAuthority: {
      userId: USER_ID,
      deviceId,
      workspaceId,
      userAuditCheckpointHash: hash("user-audit-checkpoint"),
      workspaceAuditCheckpointHash: candidate.signed_checkpoint.checkpoint_hash,
      userKeyDirectoryCheckpointHash: hash("user-key-directory-checkpoint"),
      workspaceKeyDirectoryCheckpointHash: checkpointHash(checkpoint as never),
    },
  };
}

function transferredWorkspacePin(workspaceId: string): AuditCheckpointPin {
  return {
    protocol: "refmd.audit-checkpoint-pin",
    version: 1,
    chain_scope_kind: "workspace",
    chain_scope_id: workspaceId,
    checkpoint_sequence: 1,
    checkpoint_hash: hash(`checkpoint:${workspaceId}`),
    event_head_sequence: 1,
    event_head_hash: hash(`event:${workspaceId}`),
    checkpoint_variant: "workspace_device",
    signer_owner_kind: "device",
    signer_owner_id: "00000000-0000-4000-8000-000000000013",
    signing_key_id: hash(`signing-key:${workspaceId}`),
    authorization_checkpoint_sequence: 1,
    authorization_checkpoint_hash: hash(`authority:${workspaceId}`),
    trust_state: "anchored",
    anchor_evidence_hash: hash(`evidence:${workspaceId}`),
  };
}

function transferredUserPin(userId: string): AuditCheckpointPin {
  return {
    ...transferredWorkspacePin(userId),
    chain_scope_kind: "user",
    chain_scope_id: userId,
    checkpoint_variant: "user_identity",
    signer_owner_kind: "identity",
    signer_owner_id: userId,
  };
}

function keyDirectoryPin(scopeKind: "user" | "workspace", scopeId: string) {
  return {
    pinKey: `${scopeKind}:${scopeId}`,
    scopeKind,
    scopeId,
    checkpointSequence: 1,
    checkpointHash: hash(`kd-checkpoint:${scopeId}`),
    eventHeadSequence: 1,
    eventHeadHash: hash(`kd-event:${scopeId}`),
    suitePolicyVersion: 1,
    minSuiteRank: 1000,
    allowedSuiteIdsHash: hash(`suite:${scopeId}`),
    observedAt: 1,
  };
}

function hash(label: string): string {
  return blake3Base64Url(new TextEncoder().encode(label));
}

function zeroSignature(length: number): string {
  return btoa(String.fromCharCode(...new Uint8Array(length)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
