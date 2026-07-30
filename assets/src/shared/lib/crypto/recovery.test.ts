import { describe, expect, it } from "vite-plus/test";
import { deriveRecoveryAuthorizationKey } from "./recovery";
import { computeSigningKeyId } from "./signature";

describe("recovery authorization key", () => {
  it("derives a dedicated recovery_authorization owner", () => {
    const userId = crypto.randomUUID();
    const first = deriveRecoveryAuthorizationKey(new Uint8Array(32).fill(7), userId);
    const second = deriveRecoveryAuthorizationKey(new Uint8Array(32).fill(7), userId);

    expect(first.publicKeyMaterial).toEqual(second.publicKeyMaterial);
    expect(first.privateKeyMaterial.owner_kind).toBe("recovery_authorization");
    expect(first.publicKeyMaterial.owner_kind).toBe("recovery_authorization");
    expect(first.publicKeyMaterial.owner_id).toBe(userId);
    expect(first.keyId).toBe(computeSigningKeyId(first.publicKeyMaterial));
  });
});
