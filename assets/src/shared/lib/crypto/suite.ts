import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, compareUtf8 } from "./jcs";

export const SUITE_IDS = {
  SIGNED_PQ_HYBRID_WRAP:
    "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
  HYBRID_SIGNATURE: "refmd-v2-hybrid-signature-ed25519-mldsa65",
  INITIAL_AKE: "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
  INITIAL_DELIVERY: "refmd-v2-initial-delivery-xchacha20poly1305",
} as const;

export const CURRENT_PROTOCOL_VERSION = 1;
export const CURRENT_SUITE_RANK = 1000;
export const CURRENT_SUITE_POLICY_VERSION = 1;

const CURRENT_ALLOWED_SUITE_IDS = Object.values(SUITE_IDS).sort(compareUtf8);
const CURRENT_REQUIRED_COMPONENTS = ["ed25519", "mldsa65", "mlkem768", "x25519"].sort(compareUtf8);

export interface SuitePolicy {
  suite_policy_version: number;
  min_suite_rank: number;
  allowed_suite_ids: string[];
  required_components: string[];
  allowed_suite_ids_hash?: string;
}

export interface PinnedSuitePolicy {
  suite_policy_version: number;
  min_suite_rank: number;
  allowed_suite_ids_hash: string;
}

export function currentSuitePolicy(): SuitePolicy {
  return {
    suite_policy_version: CURRENT_SUITE_POLICY_VERSION,
    min_suite_rank: CURRENT_SUITE_RANK,
    allowed_suite_ids: [...CURRENT_ALLOWED_SUITE_IDS],
    required_components: [...CURRENT_REQUIRED_COMPONENTS],
    allowed_suite_ids_hash: canonicalAllowedSuiteIdsHash({
      allowed_suite_ids: [...CURRENT_ALLOWED_SUITE_IDS],
    }),
  };
}

export function assertProtocolVersion(protocolVersion: number): void {
  if (protocolVersion !== CURRENT_PROTOCOL_VERSION) {
    throw new Error("protocol_version_not_allowed");
  }
}

export function assertKnownSuiteId(
  suiteId: string,
  policy: SuitePolicy = currentSuitePolicy(),
): void {
  assertSuitePolicyShape(policy);
  if (!policy.allowed_suite_ids.includes(suiteId)) {
    throw new Error("suite_id_not_allowed");
  }
}

export function assertSuiteRankAllowed(
  suiteId: string,
  suiteRank: number,
  policy: SuitePolicy = currentSuitePolicy(),
): void {
  assertKnownSuiteId(suiteId, policy);
  if (suiteRank < policy.min_suite_rank || suiteRank !== CURRENT_SUITE_RANK) {
    throw new Error("suite_rank_not_allowed");
  }
}

export function assertRequiredComponents(policy: SuitePolicy): void {
  assertCanonicalSortedUnique(policy.required_components, "required_components");
  if (
    policy.required_components.length !== CURRENT_REQUIRED_COMPONENTS.length ||
    policy.required_components.some((component, i) => component !== CURRENT_REQUIRED_COMPONENTS[i])
  ) {
    throw new Error("required_components_mismatch");
  }
}

export function canonicalAllowedSuiteIdsHash(
  policy: Pick<SuitePolicy, "allowed_suite_ids">,
): string {
  assertCanonicalSortedUnique(policy.allowed_suite_ids, "allowed_suite_ids");
  return blake3Base64Url(canonicalizeStrictBytes({ allowed_suite_ids: policy.allowed_suite_ids }));
}

export function assertPinnedSuitePolicy(policy: SuitePolicy, pinned: PinnedSuitePolicy): void {
  assertSuitePolicyShape(policy);
  if (policy.suite_policy_version < pinned.suite_policy_version) {
    throw new Error("suite_policy_version_rollback");
  }
  if (policy.min_suite_rank < pinned.min_suite_rank) {
    throw new Error("min_suite_rank_rollback");
  }
  if (canonicalAllowedSuiteIdsHash(policy) !== pinned.allowed_suite_ids_hash) {
    throw new Error("allowed_suite_ids_hash_mismatch");
  }
}

function assertSuitePolicyShape(policy: SuitePolicy): void {
  assertCanonicalSortedUnique(policy.allowed_suite_ids, "allowed_suite_ids");
  const hash = canonicalAllowedSuiteIdsHash(policy);
  if (policy.allowed_suite_ids_hash !== undefined && policy.allowed_suite_ids_hash !== hash) {
    throw new Error("allowed_suite_ids_hash_mismatch");
  }
  if (!CURRENT_ALLOWED_SUITE_IDS.every((suiteId) => policy.allowed_suite_ids.includes(suiteId))) {
    throw new Error("allowed_suite_ids_incomplete");
  }
  if (policy.allowed_suite_ids.length !== CURRENT_ALLOWED_SUITE_IDS.length) {
    throw new Error("allowed_suite_ids_unknown");
  }
  assertRequiredComponents(policy);
}

function assertCanonicalSortedUnique(values: string[], field: string): void {
  const seen = new Set<string>();
  for (let i = 0; i < values.length; i += 1) {
    const value = values[i]!;
    if (seen.has(value)) throw new Error(`${field}_duplicate`);
    seen.add(value);
    if (i > 0 && compareUtf8(values[i - 1]!, value) >= 0) {
      throw new Error(`${field}_not_canonical`);
    }
  }
}
