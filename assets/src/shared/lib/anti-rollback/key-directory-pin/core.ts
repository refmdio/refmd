import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { currentSuitePolicy } from "@/shared/lib/crypto/suite";
import type { KeyDirectoryPin } from "./types";
import { numberField, stringField } from "./primitives";

export function pinFromCheckpoint(
  scopeKind: "user" | "workspace",
  scopeId: string,
  envelope: { payload?: unknown },
): KeyDirectoryPin {
  const payload = envelope.payload as Record<string, unknown> | undefined;
  if (!payload) throw new Error("key_directory_checkpoint_payload_invalid");
  const coveredHead = payload.covered_event_head as Record<string, unknown> | undefined;
  if (!coveredHead) throw new Error("key_directory_checkpoint_head_invalid");

  if (payload.scope_kind !== scopeKind || payload.scope_id !== scopeId) {
    throw new Error("key_directory_checkpoint_scope_mismatch");
  }

  const allowedSuiteIds = payload.allowed_suite_ids as string[] | undefined;
  if (!Array.isArray(allowedSuiteIds)) {
    throw new Error("key_directory_checkpoint_suite_policy_invalid");
  }
  const suitePolicy = currentSuitePolicy();
  const allowedSuiteIdsHash = blake3Base64Url(
    canonicalizeStrictBytes({ allowed_suite_ids: allowedSuiteIds }),
  );

  if (
    payload.suite_policy_version !== suitePolicy.suite_policy_version ||
    payload.min_suite_rank !== suitePolicy.min_suite_rank ||
    allowedSuiteIdsHash !== suitePolicy.allowed_suite_ids_hash
  ) {
    throw new Error("key_directory_checkpoint_suite_policy_invalid");
  }

  return {
    pinKey: `${scopeKind}:${scopeId}`,
    scopeKind,
    scopeId,
    checkpointSequence: numberField(payload.sequence, "checkpoint_sequence_invalid"),
    checkpointHash: blake3Base64Url(canonicalizeStrictBytes(payload as StrictJsonValue)),
    eventHeadSequence: numberField(coveredHead.head_sequence, "event_head_sequence_invalid"),
    eventHeadHash: stringField(coveredHead.head_hash, "event_head_hash_invalid"),
    suitePolicyVersion: numberField(payload.suite_policy_version, "suite_policy_version_invalid"),
    minSuiteRank: numberField(payload.min_suite_rank, "min_suite_rank_invalid"),
    allowedSuiteIdsHash,
    observedAt: Date.now(),
  };
}
