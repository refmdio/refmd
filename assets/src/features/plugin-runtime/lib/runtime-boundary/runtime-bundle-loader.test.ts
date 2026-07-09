import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import {
  computeSigningKeyId,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
} from "@/shared/lib/crypto/signature";
import { createDefaultPluginRuntimeSignerKeyResolver } from "./runtime-bundle-loader";
import type {
  PluginRuntimeBundleEnvelope,
  PluginRuntimeSignatureProofEnvelope,
} from "./runtime-types";

const mocks = vi.hoisted(() => ({
  deviceState: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

beforeEach(() => {
  mocks.deviceState.mockReturnValue({ deviceId: "rrp-device-one" });
  mocks.fetchVerifiedKeyDirectory.mockReset();
});

describe("default plugin runtime signer key resolver", () => {
  it("loads user key directory for user-owned approval proofs", async () => {
    const signed = signedProof("user-one", "workspace-one");
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({
      checkpoint: { payload: keyDirectoryPayload(signed.signingKeyId, signed.publicKeyMaterial) },
    });

    const resolver = createDefaultPluginRuntimeSignerKeyResolver();
    await expect(
      resolver(
        {
          ...signed.proof,
          subject: {
            owner_scope_kind: "user",
            owner_user_id: "user-one",
          },
        },
        "approval",
        bundleEnvelope(),
      ),
    ).resolves.toEqual(signed.publicKeyMaterial);

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledWith({
      scopeKind: "user",
      scopeId: "user-one",
      rrpDeviceId: "rrp-device-one",
    });
  });

  it("loads actor scope key directory for consent proofs", async () => {
    const signed = signedProof("user-one", "workspace-one");
    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({
      checkpoint: { payload: keyDirectoryPayload(signed.signingKeyId, signed.publicKeyMaterial) },
    });

    const resolver = createDefaultPluginRuntimeSignerKeyResolver();
    await expect(resolver(signed.proof, "consent", bundleEnvelope())).resolves.toEqual(
      signed.publicKeyMaterial,
    );

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId: "workspace-one",
      rrpDeviceId: "rrp-device-one",
    });
  });
});

function signedProof(userId: string, scopeId: string) {
  const deviceId = "device-one";
  const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", deviceId);
  const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
  const signingKeyId = computeSigningKeyId(publicKeyMaterial);
  const proof: PluginRuntimeSignatureProofEnvelope = {
    event_hash: "event-hash-one",
    subject: {},
    actor: {
      signer_kind: "device",
      user_id: userId,
      device_id: deviceId,
      signing_key_id: signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: scopeId,
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: "checkpoint-hash-one",
    },
    signing_key_id: signingKeyId,
    hybrid_signature: {} as never,
  };
  return { proof, publicKeyMaterial, signingKeyId };
}

function keyDirectoryPayload(signingKeyId: string, keyMaterial: unknown) {
  return {
    protocol: "refmd.key-directory-checkpoint",
    identity_keys: [],
    device_keys: [
      {
        key_id: signingKeyId,
        key_material: keyMaterial,
      },
    ],
  };
}

function bundleEnvelope(): PluginRuntimeBundleEnvelope {
  return {} as PluginRuntimeBundleEnvelope;
}
