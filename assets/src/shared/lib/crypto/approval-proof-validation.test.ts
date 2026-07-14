import { describe, expect, it } from "vite-plus/test";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes } from "./jcs";
import { pendingDeliveryRecordHashFromArtifact } from "./approval-proof-validation";

describe("device approval delivery artifact validation", () => {
  it("binds a finalized delivery to its pre-confirmation pending delivery", () => {
    const pendingDelivery = {
      metadata: {
        delivery_id: "delivery-1",
        recipient_device_id: "recipient-1",
      },
      aead: {
        ciphertext: "ciphertext",
        nonce: "nonce",
      },
    };
    const finalizedDelivery = {
      protocol: "refmd.initial-key-delivery",
      metadata: {
        ...pendingDelivery.metadata,
        key_confirmation_hash: "confirmation-hash",
      },
      aead: pendingDelivery.aead,
      signature: { signature: "signature" },
    };
    const pendingHash = blake3Base64Url(canonicalizeStrictBytes(pendingDelivery));

    expect(pendingHash).not.toBe(blake3Base64Url(canonicalizeStrictBytes(finalizedDelivery)));

    expect(
      pendingDeliveryRecordHashFromArtifact({
        initial_key_delivery: finalizedDelivery,
      }),
    ).toBe(pendingHash);
  });
});
