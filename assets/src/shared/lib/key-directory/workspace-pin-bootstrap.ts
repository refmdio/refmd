import {
  hashKeyDirectoryCheckpointEnvelope,
  installVerifiedTransferredKeyDirectoryCheckpoint,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { verifyCheckpointSignatures } from "@/shared/lib/anti-rollback/key-directory-pin/verification";
import {
  assertKeyEntryActiveAtSequence,
  assertEnvelope,
  eventHash,
  assertSignerMatchesMaterial,
  isRecord,
  numberField as keyDirectoryNumberField,
  signingKeyMaterialById,
} from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import { assertBase64Url, base64UrlEncode, randomBytes } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { HybridSignature } from "@/shared/lib/crypto/signature-types";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

const PROTOCOL = "refmd.workspace-pin-bootstrap";
const VERSION = 1;
const MAX_SAFE_EVENT_SEQUENCE = Number.MAX_SAFE_INTEGER;
const BOOTSTRAP_ENVELOPE_KEYS = ["payload", "signatures"];
const BOOTSTRAP_PAYLOAD_KEYS = [
  "allowed_suite_ids_hash",
  "bootstrap_nonce",
  "checkpoint_hash",
  "checkpoint_sequence",
  "event_head_hash",
  "event_head_sequence",
  "expires_event_sequence",
  "issuer",
  "issuing_event_hash",
  "min_suite_rank",
  "protocol",
  "suite_policy_version",
  "version",
  "workspace_id",
];
const BOOTSTRAP_ISSUER_KEYS = [
  "device_id",
  "key_checkpoint_hash",
  "key_checkpoint_sequence",
  "key_scope_id",
  "key_scope_kind",
  "signer_kind",
  "signing_key_id",
  "user_id",
];
const BOOTSTRAP_SIGNATURE_ENVELOPE_KEYS = ["signature", "signer"];

function recordWorkspacePinBootstrapPerf(event: string, detail: Record<string, unknown>): void {
  if (typeof window === "undefined" || !window.__REFMD_E2E__) return;
  const payload = {
    event,
    detail,
    at: Date.now(),
    now: performance.now(),
  };
  const target = window as Window & { __refmdE2ESyncPerf?: unknown[] };
  target.__refmdE2ESyncPerf ??= [];
  target.__refmdE2ESyncPerf.push(payload);
  window.dispatchEvent(new CustomEvent("refmd:sync-perf", { detail: payload }));
}

export interface WorkspacePinBootstrapEnvelope {
  payload: WorkspacePinBootstrapPayload;
  signatures: Array<{
    signer: WorkspacePinBootstrapIssuer;
    signature: HybridSignature;
  }>;
}

export interface WorkspacePinBootstrapIssuer {
  signer_kind: "device";
  user_id: string;
  device_id: string;
  signing_key_id: string;
  key_scope_kind: "workspace";
  key_scope_id: string;
  key_checkpoint_sequence: number;
  key_checkpoint_hash: string;
}

export interface WorkspacePinBootstrapPayload {
  protocol: "refmd.workspace-pin-bootstrap";
  version: 1;
  workspace_id: string;
  checkpoint_sequence: number;
  checkpoint_hash: string;
  event_head_sequence: number;
  event_head_hash: string;
  suite_policy_version: number;
  min_suite_rank: number;
  allowed_suite_ids_hash: string;
  issuer: WorkspacePinBootstrapIssuer;
  issuing_event_hash: string;
  expires_event_sequence: number;
  bootstrap_nonce: string;
}

function recordField(value: unknown, code: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(code);
  return value;
}

function numberField(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(code);
  }
  return value;
}

function positiveNumberField(value: unknown, code: string): number {
  const result = numberField(value, code);
  if (result < 1) throw new Error(code);
  return result;
}

function stringField(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function arrayField(value: unknown, code: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(code);
  return value;
}

function assertExactKeys(record: Record<string, unknown>, keys: string[], code: string): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(code);
  }
}

function assertWorkspacePinBootstrapPayload(value: unknown): Record<string, unknown> {
  const payload = recordField(value, "workspace_pin_payload_invalid");
  assertExactKeys(payload, BOOTSTRAP_PAYLOAD_KEYS, "workspace_pin_payload_invalid");
  assertExactKeys(
    recordField(payload.issuer, "workspace_pin_issuer_invalid"),
    BOOTSTRAP_ISSUER_KEYS,
    "workspace_pin_issuer_invalid",
  );
  assertBase64Url(stringField(payload.bootstrap_nonce, "workspace_pin_payload_invalid"), 32);
  return payload;
}

function assertWorkspacePinBootstrapSignatures(value: unknown): unknown[] {
  const signatures = arrayField(value, "workspace_pin_signature_invalid");
  if (signatures.length === 0) throw new Error("workspace_pin_signature_missing");
  for (const entry of signatures) {
    assertExactKeys(
      recordField(entry, "workspace_pin_signature_invalid"),
      BOOTSTRAP_SIGNATURE_ENVELOPE_KEYS,
      "workspace_pin_signature_invalid",
    );
  }
  return signatures;
}

export function assertWorkspacePinBootstrapEnvelope(
  value: unknown,
  code: string,
): WorkspacePinBootstrapEnvelope {
  const record = recordField(value, code);
  assertExactKeys(record, BOOTSTRAP_ENVELOPE_KEYS, code);
  assertWorkspacePinBootstrapPayload(record.payload);
  assertWorkspacePinBootstrapSignatures(record.signatures);
  return value as WorkspacePinBootstrapEnvelope;
}

export function buildWorkspacePinBootstrapHash(params: {
  workspaceId: string;
  bootstrap: WorkspacePinBootstrapEnvelope | Record<string, unknown>;
}): string {
  const bootstrap = assertWorkspacePinBootstrapEnvelope(
    params.bootstrap,
    "workspace_pin_bootstrap_invalid",
  );
  const payload = bootstrap.payload as unknown as Record<string, unknown>;
  if (payload.workspace_id !== params.workspaceId) {
    throw new Error("workspace_pin_workspace_mismatch");
  }
  return blake3Base64Url(canonicalizeStrictBytes(payload as StrictJsonValue));
}

export async function createWorkspacePinBootstrap(params: {
  workspaceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  actorUserId: string;
  actorDeviceId: string;
}): Promise<{ hash: string; bootstrap: WorkspacePinBootstrapEnvelope }> {
  const checkpointPayload = recordField(
    params.checkpointEnvelope.payload,
    "workspace_pin_checkpoint_invalid",
  );
  const coveredHead = recordField(
    checkpointPayload.covered_event_head,
    "workspace_pin_event_head_invalid",
  );
  const checkpointHash = hashKeyDirectoryCheckpointEnvelope(params.checkpointEnvelope);
  const signingKeyId = activeDeviceSigningKeyId(checkpointPayload, params.actorDeviceId);
  const allowedSuiteIds = arrayField(
    checkpointPayload.allowed_suite_ids,
    "workspace_pin_suite_policy_invalid",
  );
  const payload: WorkspacePinBootstrapPayload = {
    protocol: PROTOCOL,
    version: VERSION,
    workspace_id: params.workspaceId,
    checkpoint_sequence: positiveNumberField(
      checkpointPayload.sequence,
      "workspace_pin_sequence_invalid",
    ),
    checkpoint_hash: checkpointHash,
    event_head_sequence: numberField(
      coveredHead.head_sequence,
      "workspace_pin_head_sequence_invalid",
    ),
    event_head_hash: stringField(coveredHead.head_hash, "workspace_pin_head_hash_invalid"),
    suite_policy_version: positiveNumberField(
      checkpointPayload.suite_policy_version,
      "workspace_pin_suite_policy_invalid",
    ),
    min_suite_rank: positiveNumberField(
      checkpointPayload.min_suite_rank,
      "workspace_pin_suite_policy_invalid",
    ),
    allowed_suite_ids_hash: blake3Base64Url(
      canonicalizeStrictBytes({ allowed_suite_ids: allowedSuiteIds as StrictJsonValue[] }),
    ),
    issuer: {
      signer_kind: "device",
      user_id: params.actorUserId,
      device_id: params.actorDeviceId,
      signing_key_id: signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: params.workspaceId,
      key_checkpoint_sequence: positiveNumberField(
        checkpointPayload.sequence,
        "workspace_pin_sequence_invalid",
      ),
      key_checkpoint_hash: checkpointHash,
    },
    issuing_event_hash: stringField(coveredHead.head_hash, "workspace_pin_head_hash_invalid"),
    expires_event_sequence: MAX_SAFE_EVENT_SEQUENCE,
    bootstrap_nonce: base64UrlEncode(randomBytes(32)),
  };
  const signed = await getCryptoWorker().signWorkspacePinBootstrap({
    workspaceId: params.workspaceId,
    bootstrapPayload: payload as unknown as Record<string, unknown>,
  });
  const bootstrap: WorkspacePinBootstrapEnvelope = {
    payload,
    signatures: [
      {
        signer: signed.signer as unknown as WorkspacePinBootstrapIssuer,
        signature: signed.signature,
      },
    ],
  };
  return {
    hash: buildWorkspacePinBootstrapHash({ workspaceId: params.workspaceId, bootstrap }),
    bootstrap,
  };
}

export async function verifyAndInstallWorkspacePinBootstrap(params: {
  workspaceId: string;
  authenticatedWorkspacePinBootstrapHash: string;
  bootstrap: WorkspacePinBootstrapEnvelope;
  checkpointEnvelope: KeyDirectoryEnvelope;
  workspaceKeyDirectoryEventAncestry?: KeyDirectoryEnvelope[];
  operationSequence: number;
}): Promise<void> {
  const startedAt = performance.now();
  recordWorkspacePinBootstrapPerf("workspace_pin_bootstrap_verify_started", {
    workspaceId: params.workspaceId,
  });
  const bootstrap = assertWorkspacePinBootstrapEnvelope(
    params.bootstrap,
    "workspace_pin_bootstrap_invalid",
  );
  assertWorkspacePinBootstrapHash({
    workspaceId: params.workspaceId,
    authenticatedWorkspacePinBootstrapHash: params.authenticatedWorkspacePinBootstrapHash,
    bootstrap,
  });
  const checkpoint = assertEnvelope(
    params.checkpointEnvelope as unknown as Record<string, unknown>,
  );
  const payload = bootstrap.payload as unknown as Record<string, unknown>;
  const checkpointPayload = recordField(checkpoint.payload, "workspace_pin_checkpoint_invalid");
  const coveredHead = recordField(
    checkpointPayload.covered_event_head,
    "workspace_pin_event_head_invalid",
  );
  const checkpointHash = hashKeyDirectoryCheckpointEnvelope(
    checkpoint as unknown as Record<string, unknown>,
  );

  if (
    payload.protocol !== PROTOCOL ||
    payload.version !== VERSION ||
    payload.workspace_id !== params.workspaceId ||
    payload.checkpoint_sequence !== checkpointPayload.sequence ||
    payload.checkpoint_hash !== checkpointHash ||
    payload.event_head_sequence !== coveredHead.head_sequence ||
    payload.event_head_hash !== coveredHead.head_hash ||
    payload.suite_policy_version !== checkpointPayload.suite_policy_version ||
    payload.min_suite_rank !== checkpointPayload.min_suite_rank ||
    payload.allowed_suite_ids_hash !==
      blake3Base64Url(
        canonicalizeStrictBytes({
          allowed_suite_ids: arrayField(
            checkpointPayload.allowed_suite_ids,
            "workspace_pin_suite_policy_invalid",
          ) as StrictJsonValue[],
        }),
      ) ||
    numberField(payload.expires_event_sequence, "workspace_pin_expires_invalid") <
      numberField(params.operationSequence, "workspace_pin_operation_sequence_invalid")
  ) {
    throw new Error("workspace_pin_bootstrap_payload_mismatch");
  }
  recordWorkspacePinBootstrapPerf("workspace_pin_bootstrap_payload_verified", {
    workspaceId: params.workspaceId,
    elapsedMs: performance.now() - startedAt,
  });
  assertIssuingEventCovered({
    issuingEventHash: stringField(payload.issuing_event_hash, "workspace_pin_payload_invalid"),
    eventHeadSequence: numberField(
      payload.event_head_sequence,
      "workspace_pin_head_sequence_invalid",
    ),
    eventHeadHash: stringField(payload.event_head_hash, "workspace_pin_head_hash_invalid"),
    eventAncestry: params.workspaceKeyDirectoryEventAncestry ?? [],
  });
  recordWorkspacePinBootstrapPerf("workspace_pin_bootstrap_issuing_event_verified", {
    workspaceId: params.workspaceId,
    elapsedMs: performance.now() - startedAt,
  });

  const issuer = recordField(payload.issuer, "workspace_pin_issuer_invalid");
  if (
    issuer.signer_kind !== "device" ||
    issuer.key_scope_kind !== "workspace" ||
    issuer.key_scope_id !== params.workspaceId ||
    issuer.key_checkpoint_sequence !== checkpointPayload.sequence ||
    issuer.key_checkpoint_hash !== checkpointHash
  ) {
    throw new Error("workspace_pin_issuer_invalid");
  }
  assertKeyEntryActiveAtSequence(
    checkpointPayload,
    stringField(issuer.signing_key_id, "workspace_pin_issuer_invalid"),
    numberField(payload.event_head_sequence, "workspace_pin_head_sequence_invalid"),
  );
  const material = signingKeyMaterialById(checkpointPayload).get(
    stringField(issuer.signing_key_id, "workspace_pin_issuer_invalid"),
  );
  if (!material) throw new Error("workspace_pin_signer_unknown");
  assertSignerMatchesMaterial(issuer, material);
  const signatureEnvelope = bootstrap.signatures.find(
    (entry) =>
      isRecord(entry) &&
      isRecord(entry.signer) &&
      entry.signer.signer_kind === "device" &&
      entry.signer.signing_key_id === issuer.signing_key_id,
  );
  if (!signatureEnvelope) throw new Error("workspace_pin_signature_missing");
  recordWorkspacePinBootstrapPerf("workspace_pin_bootstrap_signer_verified", {
    workspaceId: params.workspaceId,
    elapsedMs: performance.now() - startedAt,
  });
  const bootstrapSignaturePromise = getCryptoWorker()
    .verifyWorkspacePinBootstrapSignature({
      workspaceId: params.workspaceId,
      bootstrapPayload: payload as unknown as StrictJsonValue,
      signature: signatureEnvelope.signature,
      publicKeyMaterial: material,
    })
    .then((valid) => {
      recordWorkspacePinBootstrapPerf("workspace_pin_bootstrap_signature_verified", {
        workspaceId: params.workspaceId,
        elapsedMs: performance.now() - startedAt,
        valid,
      });
      return valid;
    });
  const checkpointSignaturePromise = verifyCheckpointSignatures(
    checkpoint,
    checkpoint.payload,
  ).then(() => {
    recordWorkspacePinBootstrapPerf("workspace_pin_bootstrap_checkpoint_verified", {
      workspaceId: params.workspaceId,
      elapsedMs: performance.now() - startedAt,
      signatureCount: checkpoint.signatures.length,
    });
  });
  const [valid] = await Promise.all([bootstrapSignaturePromise, checkpointSignaturePromise]);
  if (!valid) throw new Error("workspace_pin_signature_invalid");

  await installVerifiedTransferredKeyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    checkpointEnvelope: checkpoint,
  });
  recordWorkspacePinBootstrapPerf("workspace_pin_bootstrap_installed", {
    workspaceId: params.workspaceId,
    elapsedMs: performance.now() - startedAt,
  });
}

export function assertWorkspacePinBootstrapHash(params: {
  workspaceId: string;
  authenticatedWorkspacePinBootstrapHash: string;
  bootstrap: WorkspacePinBootstrapEnvelope;
}): void {
  if (
    buildWorkspacePinBootstrapHash({
      workspaceId: params.workspaceId,
      bootstrap: params.bootstrap,
    }) !== params.authenticatedWorkspacePinBootstrapHash
  ) {
    throw new Error("workspace_pin_bootstrap_hash_mismatch");
  }
}

function assertIssuingEventCovered(params: {
  issuingEventHash: string;
  eventHeadSequence: number;
  eventHeadHash: string;
  eventAncestry: KeyDirectoryEnvelope[];
}): void {
  if (params.issuingEventHash === params.eventHeadHash) return;

  const events = params.eventAncestry
    .map((event) => assertEnvelope(event as unknown as Record<string, unknown>))
    .filter(
      (event) =>
        keyDirectoryNumberField(event.payload.sequence, "event_sequence_invalid") <=
        params.eventHeadSequence,
    )
    .sort(
      (left, right) =>
        keyDirectoryNumberField(left.payload.sequence, "event_sequence_invalid") -
        keyDirectoryNumberField(right.payload.sequence, "event_sequence_invalid"),
    );
  const issuingIndex = events.findIndex((event) => eventHash(event) === params.issuingEventHash);
  if (issuingIndex < 0) throw new Error("workspace_pin_issuing_event_missing");

  let previousHash = params.issuingEventHash;
  for (const event of events.slice(issuingIndex + 1)) {
    const previous = stringField(
      event.payload.previous_event_hash,
      "workspace_pin_event_chain_invalid",
    );
    if (previous !== previousHash) continue;
    previousHash = eventHash(event);
    if (
      keyDirectoryNumberField(event.payload.sequence, "event_sequence_invalid") ===
        params.eventHeadSequence &&
      previousHash === params.eventHeadHash
    ) {
      return;
    }
  }

  throw new Error("workspace_pin_issuing_event_not_covered");
}

function activeDeviceSigningKeyId(
  checkpointPayload: Record<string, unknown>,
  deviceId: string,
): string {
  for (const entry of arrayField(
    checkpointPayload.device_keys,
    "workspace_pin_device_keys_invalid",
  )) {
    if (!isRecord(entry)) continue;
    const keyMaterial = entry.key_material;
    if (
      isRecord(keyMaterial) &&
      keyMaterial.owner_kind === "device" &&
      keyMaterial.owner_id === deviceId &&
      !("revoked_at" in entry)
    ) {
      return stringField(entry.key_id, "workspace_pin_signing_key_invalid");
    }
  }
  throw new Error("workspace_pin_signing_key_missing");
}
