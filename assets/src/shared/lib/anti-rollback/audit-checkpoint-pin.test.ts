import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { AuditCheckpointPin } from "./audit-checkpoint-pin";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";

const pins = new Map<string, AuditCheckpointPin>();
const verifiedAuthorityCheckpoints: Array<{
  payload: Record<string, unknown>;
  signatures: Record<string, unknown>[];
}> = [];

vi.mock("./key-directory-pin/pins", async () => {
  const { checkpointHash } = await import("./key-directory-pin/primitives");
  return {
    hasVerifiedKeyDirectoryCheckpoint: (
      _scopeKind: string,
      _scopeId: string,
      sequence: number,
      hash: string,
    ) =>
      verifiedAuthorityCheckpoints.some(
        (checkpoint) =>
          checkpoint.payload.sequence === sequence && checkpointHash(checkpoint as never) === hash,
      ),
    lookupVerifiedKeyDirectoryCheckpointBodies: () => verifiedAuthorityCheckpoints,
  };
});
vi.mock("@/shared/lib/storage/idb", () => ({
  openIdb: vi.fn(async () => ({ close: vi.fn() })),
  idbGet: vi.fn(async (_db: unknown, _store: string, key: string) => pins.get(key)),
  idbConditionalPut: vi.fn(
    async (
      _db: unknown,
      _store: string,
      key: string,
      value: AuditCheckpointPin,
      predicate: (existing: AuditCheckpointPin | undefined) => boolean,
    ) => {
      const existing = pins.get(key);
      if (!predicate(existing)) return false;
      pins.set(key, value);
      return true;
    },
  ),
}));

describe("audit checkpoint pins", () => {
  beforeEach(() => {
    pins.clear();
    verifiedAuthorityCheckpoints.length = 0;
    verifiedAuthorityCheckpoints.push(checkpoint(1).authority_checkpoint);
  });

  it("pins and monotonically advances a checkpoint under its signed authority scope", async () => {
    const { getAuditCheckpointPin, verifyAndPinAuditCheckpoint } =
      await import("./audit-checkpoint-pin");
    await verifyAndPinAuditCheckpoint(checkpoint(1));
    const second = checkpoint(2);
    expect(checkpoint(1).event_hash).toBe("HU1dtcByO0M8vycTqzGI0YKY34i6idnAAtyOIEjiEDg");
    await verifyAndPinAuditCheckpoint(second);

    await expect(getAuditCheckpointPin("user:user-one")).resolves.toMatchObject({
      sequence: 2,
      eventHash: second.event_hash,
    });
  });

  it("verifies a pending-device checkpoint without installing a durable pin", async () => {
    const { getAuditCheckpointPin, verifyAuditCheckpointCandidate } =
      await import("./audit-checkpoint-pin");

    await expect(verifyAuditCheckpointCandidate(checkpoint(1))).resolves.toMatchObject({
      chainScope: "user:user-one",
      sequence: 1,
    });
    await expect(getAuditCheckpointPin("user:user-one")).resolves.toBeNull();
  });

  it("rejects rollback and same-sequence forks", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const current = checkpoint(2);
    await verifyAndPinAuditCheckpoint(current);

    await expect(verifyAndPinAuditCheckpoint(checkpoint(1))).rejects.toThrow(
      "audit_checkpoint_rollback_or_fork",
    );
    await expect(
      verifyAndPinAuditCheckpoint({ ...current, event_hash: hash("c") }),
    ).rejects.toThrow("audit_checkpoint_rollback_or_fork");
  });

  it("rejects a checkpoint whose signed authority belongs to another scope", async () => {
    const { verifyAndPinAuditCheckpoint } = await import("./audit-checkpoint-pin");
    const candidate = checkpoint(1);
    candidate.authority_checkpoint.payload.scope_id = "other-user";

    await expect(verifyAndPinAuditCheckpoint(candidate)).rejects.toThrow(
      "audit_checkpoint_authority_scope_mismatch",
    );
  });

  it("installs an authenticated Trust Transfer pin without replacing a conflicting pin", async () => {
    const { getAuditCheckpointPin, installTransferredAuditCheckpointPin } =
      await import("./audit-checkpoint-pin");
    const transferred = {
      chainScope: "user:user-one",
      sequence: 3,
      eventHash: hash("t"),
      authorityCheckpointHash: hash("k"),
      observedAt: 1,
    };

    await installTransferredAuditCheckpointPin(transferred);
    await expect(getAuditCheckpointPin(transferred.chainScope)).resolves.toMatchObject({
      chainScope: transferred.chainScope,
      sequence: transferred.sequence,
      eventHash: transferred.eventHash,
      authorityCheckpointHash: transferred.authorityCheckpointHash,
    });
    await expect(
      installTransferredAuditCheckpointPin({ ...transferred, eventHash: hash("x") }),
    ).rejects.toThrow("audit_checkpoint_transfer_conflict");
    await expect(
      installTransferredAuditCheckpointPin({
        ...transferred,
        authorityCheckpointHash: hash("r"),
      }),
    ).rejects.toThrow("audit_checkpoint_transfer_conflict");
  });

  it("advances a transferred authority pin only through verified checkpoint ancestry", async () => {
    const { installTransferredAuditCheckpointPin, verifyAuditCheckpointCandidate } =
      await import("./audit-checkpoint-pin");
    const initial = checkpoint(1);
    const initialAuthorityHash = authorityHash(initial.authority_checkpoint);
    await installTransferredAuditCheckpointPin({
      chainScope: initial.chain_scope,
      sequence: initial.sequence,
      eventHash: initial.event_hash,
      authorityCheckpointHash: initialAuthorityHash,
      observedAt: 0,
    });

    const descendantAuthority = authorityCheckpoint(2, initialAuthorityHash);
    verifiedAuthorityCheckpoints.push(descendantAuthority);
    const candidate = checkpoint(2);
    candidate.authority_checkpoint = descendantAuthority;

    await expect(verifyAuditCheckpointCandidate(candidate)).resolves.toMatchObject({
      authorityCheckpointHash: authorityHash(descendantAuthority),
    });

    const replacement = authorityCheckpoint(3, hash("u"));
    verifiedAuthorityCheckpoints.push(replacement);
    await expect(
      verifyAuditCheckpointCandidate({ ...candidate, authority_checkpoint: replacement }),
    ).rejects.toThrow("audit_checkpoint_authority_replacement");
  });

  it("rejects an authority checkpoint outside verified key-directory lineage", async () => {
    const { installTransferredAuditCheckpointPin, verifyAuditCheckpointCandidate } =
      await import("./audit-checkpoint-pin");
    const candidate = checkpoint(1);
    await installTransferredAuditCheckpointPin({
      chainScope: candidate.chain_scope,
      sequence: candidate.sequence,
      eventHash: candidate.event_hash,
      authorityCheckpointHash: authorityHash(candidate.authority_checkpoint),
      observedAt: 0,
    });
    candidate.authority_checkpoint = authorityCheckpoint(2, hash("m"));

    await expect(verifyAuditCheckpointCandidate(candidate)).rejects.toThrow(
      "audit_checkpoint_authority_unverified",
    );
  });

  it("rejects an unverified authority checkpoint before the first audit pin", async () => {
    const { verifyAuditCheckpointCandidate } = await import("./audit-checkpoint-pin");
    verifiedAuthorityCheckpoints.length = 0;

    await expect(verifyAuditCheckpointCandidate(checkpoint(1))).rejects.toThrow(
      "audit_checkpoint_authority_unverified",
    );
  });

  it("requires exactly one matching audit pin for every transferred workspace", async () => {
    const { assertTransferredWorkspaceAuditPins } = await import("./audit-checkpoint-pin");
    const workspaceOne = transferredWorkspacePin("workspace-one");
    const workspaceTwo = transferredWorkspacePin("workspace-two");

    expect(
      assertTransferredWorkspaceAuditPins(
        ["workspace-one", "workspace-two"],
        [workspaceTwo, workspaceOne],
      ),
    ).toEqual([workspaceTwo, workspaceOne]);
    expect(() =>
      assertTransferredWorkspaceAuditPins(["workspace-one", "workspace-two"], [workspaceOne]),
    ).toThrow("trust_state_bundle_workspace_audit_pins_mismatch");
    expect(() =>
      assertTransferredWorkspaceAuditPins(["workspace-one"], [workspaceOne, workspaceOne]),
    ).toThrow("trust_state_bundle_workspace_audit_pins_mismatch");
    expect(() => assertTransferredWorkspaceAuditPins(["workspace-one"], [workspaceTwo])).toThrow(
      "trust_state_bundle_workspace_audit_pins_mismatch",
    );
  });
});

function transferredWorkspacePin(workspaceId: string): AuditCheckpointPin {
  return {
    chainScope: `workspace:${workspaceId}`,
    sequence: 1,
    eventHash: blake3Base64Url(new TextEncoder().encode(`event:${workspaceId}`)),
    authorityCheckpointHash: blake3Base64Url(new TextEncoder().encode(`authority:${workspaceId}`)),
    observedAt: 0,
  };
}

function checkpoint(sequence: number) {
  const ancestry: Record<string, unknown>[] = [];
  let previousEventHash: string | null = null;
  for (let current = 1; current <= sequence; current++) {
    const event: Record<string, unknown> = {
      protocol: "refmd.security-audit-chain",
      version: 1,
      chain_scope: "user:user-one",
      sequence: current,
      previous_event_hash: previousEventHash,
      class: "authority",
      type: `audit.event.${current}`,
      actor: { user_id: "user-one" },
      scope: {},
      resource: { kind: "user", id: "user-one" },
      action: { operation: "audit", result: "completed" },
      sensitivity: { plaintext_scope_kind: "none", plaintext_bytes: 0 },
      correlation: {},
    };
    const eventHash = blake3Base64Url(canonicalizeStrictBytes(compact(event) as StrictJsonValue));
    ancestry.push({ ...event, event_hash: eventHash });
    previousEventHash = eventHash;
  }
  return {
    chain_scope: "user:user-one",
    sequence,
    event_hash: previousEventHash!,
    ancestry,
    authority_checkpoint: {
      payload: {
        protocol: "refmd.key-directory-checkpoint",
        version: 1,
        scope_kind: "user",
        scope_id: "user-one",
        sequence: 1,
        issued_at: "2026-07-11T00:00:00Z",
        suite_policy_version: 1,
        min_suite_rank: 1,
        allowed_suite_ids: ["suite"],
        required_components: [],
        identity_keys: [],
        device_keys: [],
        share_participant_keys: [],
        revoked_key_ids: [],
        covered_event_head: { head_sequence: 1, head_hash: hash("k") },
      },
      signatures: [{ signer: {}, signature: {} }],
    },
  };
}

function authorityCheckpoint(sequence: number, previousCheckpointHash?: string) {
  const checkpointValue = checkpoint(1).authority_checkpoint;
  return {
    ...checkpointValue,
    payload: {
      ...checkpointValue.payload,
      sequence,
      ...(previousCheckpointHash ? { previous_checkpoint_hash: previousCheckpointHash } : {}),
    },
  };
}

function authorityHash(authority: ReturnType<typeof authorityCheckpoint>): string {
  return blake3Base64Url(canonicalizeStrictBytes(authority.payload as unknown as StrictJsonValue));
}

function compact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(compact);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== null && nested !== undefined)
      .map(([key, nested]) => [key, compact(nested)]),
  );
}

function hash(character: string): string {
  return character.repeat(43);
}
