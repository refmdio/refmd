import { describe, expect, it } from "vitest";
import {
  assertKnownSuiteId,
  assertPinnedSuitePolicy,
  assertProtocolVersion,
  assertRequiredComponents,
  assertSuiteRankAllowed,
  canonicalAllowedSuiteIdsHash,
  currentSuitePolicy,
  SUITE_IDS,
} from "./suite";

describe("suite admission", () => {
  it("validates current suite policy and pinned allowed-suite hash", () => {
    const policy = currentSuitePolicy();
    expect(policy.allowed_suite_ids_hash).toBe("OcQ3VH6UrkTrIXcahgjG7weNblUpExxAM0rB5KqOVts");
    expect(canonicalAllowedSuiteIdsHash(policy)).toBe(policy.allowed_suite_ids_hash);
    expect(() => assertProtocolVersion(1)).not.toThrow();
    expect(() => assertKnownSuiteId(SUITE_IDS.INITIAL_AKE, policy)).not.toThrow();
    expect(() => assertSuiteRankAllowed(SUITE_IDS.HYBRID_SIGNATURE, 1000, policy)).not.toThrow();
    expect(() => assertRequiredComponents(policy)).not.toThrow();
    expect(() =>
      assertPinnedSuitePolicy(policy, {
        suite_policy_version: 1,
        min_suite_rank: 1000,
        allowed_suite_ids_hash: policy.allowed_suite_ids_hash!,
      }),
    ).not.toThrow();
  });

  it("rejects protocol and suite downgrades", () => {
    const policy = currentSuitePolicy();
    expect(() => assertProtocolVersion(0)).toThrow();
    expect(() => assertProtocolVersion(2)).toThrow();
    expect(() => assertKnownSuiteId("refmd-v1-static-dh", policy)).toThrow();
    expect(() => assertSuiteRankAllowed(SUITE_IDS.HYBRID_SIGNATURE, 999, policy)).toThrow();
    expect(() =>
      assertPinnedSuitePolicy(
        { ...policy, allowed_suite_ids: policy.allowed_suite_ids.slice(1) },
        {
          suite_policy_version: 1,
          min_suite_rank: 1000,
          allowed_suite_ids_hash: policy.allowed_suite_ids_hash!,
        },
      ),
    ).toThrow();
    expect(() =>
      assertKnownSuiteId("refmd-v2-unknown-extra", {
        ...policy,
        allowed_suite_ids: [...policy.allowed_suite_ids, "refmd-v2-unknown-extra"].sort(),
      }),
    ).toThrow();
    expect(() =>
      assertRequiredComponents({ ...policy, required_components: ["ed25519", "mldsa65"] }),
    ).toThrow();
  });
});
