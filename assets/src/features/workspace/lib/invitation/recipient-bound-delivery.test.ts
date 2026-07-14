import { expect, it } from "vite-plus/test";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes } from "@/shared/lib/crypto/jcs";
import { redeemFreshnessProof, type MemberGossipStatement } from "./recipient-bound-delivery";

const checkpointEnvelope = {
  payload: {
    sequence: 4,
    covered_event_head: { head_sequence: 9, head_hash: "head-hash" },
  },
  signatures: [{ signer: {}, signature: {} }],
};

const attempt = {
  workspace_id: "workspace-1",
  recipient_redeem_nonce: "redeem-nonce",
  live_redeem_challenge_hash: "challenge-hash",
};

function statement(userId: string, deviceId: string): MemberGossipStatement {
  return {
    payload: { user_id: userId, device_id: deviceId },
    transcript: {},
    signature: {},
    signing_key_id: `key-${deviceId}`,
    hybrid_signing_public_key_material: {},
  };
}

it("builds member gossip freshness with the exact canonical statement hash set", () => {
  const statements = [statement("user-1", "device-1"), statement("user-2", "device-2")];
  const proof = redeemFreshnessProof({
    attempt: attempt as never,
    checkpointEnvelope: checkpointEnvelope as never,
    actorUserId: "actor-user",
    actorDeviceId: "actor-device",
    memberGossipStatements: statements,
  });

  expect(proof.proof_kind).toBe("member_gossip_quorum");
  expect(proof.proof_hashes).toEqual(
    statements
      .map((item) => blake3Base64Url(canonicalizeStrictBytes(item.payload as never)))
      .sort(),
  );
  expect(proof.gossip_statements).toEqual(statements);
  expect(proof).not.toHaveProperty("authoritative_device");
});

it("rejects gossip quorum statements from the same user", () => {
  expect(() =>
    redeemFreshnessProof({
      attempt: attempt as never,
      checkpointEnvelope: checkpointEnvelope as never,
      actorUserId: "actor-user",
      actorDeviceId: "actor-device",
      memberGossipStatements: [statement("user-1", "device-1"), statement("user-1", "device-2")],
    }),
  ).toThrow("member_gossip_quorum_invalid");
});
