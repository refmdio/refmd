import { describe, expect, it } from "vitest";

import { assertShareBootstrapMatchesTrustAnchor } from "./session";
import type { ShareSessionTrustAnchor } from "@/shared/lib/auth/share-participant-session-store";

const hashA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const hashB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const uuidA = "11111111-1111-4111-8111-111111111111";
const uuidB = "22222222-2222-4222-8222-222222222222";
const shareSlug = "abcdefghijklmnopqrstuv";

function anchor(overrides: Partial<ShareSessionTrustAnchor> = {}): ShareSessionTrustAnchor {
  return {
    protocol: "refmd.share-session-trust-anchor",
    version: 1,
    shareSlug,
    shareTokenHash: hashA,
    shareId: uuidA,
    participantPrincipalId: "33333333-3333-4333-8333-333333333333",
    participantDeviceId: "44444444-4444-4444-8444-444444444444",
    scopeKind: "document",
    scopeId: uuidB,
    permission: "edit",
    passwordProtected: false,
    capabilitySecretHash: hashA,
    workspacePinBootstrapHash: hashA,
    createdEventHash: hashA,
    latestBootstrapEventHash: hashA,
    capabilityContextHash: hashA,
    shareCapabilitySecretCommitment: hashA,
    passwordCapabilitySecretCommitment: "none",
    sourceKind: "url_fragment",
    ...overrides,
  };
}

function bootstrap(overrides: Record<string, string | boolean> = {}) {
  return {
    share_id: uuidA,
    scope_kind: "document" as const,
    scope_id: uuidB,
    permission: "edit" as const,
    password_protected: false,
    share_token_hash: hashA,
    created_event_hash: hashA,
    latest_bootstrap_event_hash: hashB,
    capability_context_hash: hashA,
    share_capability_secret_commitment: hashA,
    password_capability_secret_commitment: "none",
    ...overrides,
  };
}

describe("share session trust anchor bootstrap matching", () => {
  it("accepts a newer latest bootstrap event hash for anchor refresh", () => {
    expect(() =>
      assertShareBootstrapMatchesTrustAnchor(shareSlug, anchor(), bootstrap()),
    ).not.toThrow();
  });

  it("still rejects immutable share identity mismatches", () => {
    expect(() =>
      assertShareBootstrapMatchesTrustAnchor(
        shareSlug,
        anchor(),
        bootstrap({ share_id: "55555555-5555-4555-8555-555555555555" }),
      ),
    ).toThrow("share_trust_anchor_mismatch");
  });
});
