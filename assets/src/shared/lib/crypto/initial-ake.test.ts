import { describe, expect, it } from "vite-plus/test";
import {
  createInitialAkeUmkDelivery,
  createInitialAkeKekDelivery,
  createInitialAkeDeviceStateTransferDelivery,
  generateInitialAkeResponderPrekey,
  openInitialAkeUmkDelivery,
} from "./initial-ake";
import { generateHybridSigningPrivateKeyMaterial, publicKeyMaterialFromPrivate } from "./signature";

describe("Initial AKE UMK delivery", () => {
  it("opens only with the matching one-time responder prekey", () => {
    const userId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientSigning = generateHybridSigningPrivateKeyMaterial("device", recipientDeviceId);
    const prekey = generateInitialAkeResponderPrekey({
      purpose: "umk_distribution",
      operationId: recipientDeviceId,
      userId,
      deviceId: recipientDeviceId,
      issuedAtEventSequence: 1,
      expiresEventSequence: 2,
      signingPrivateKeyMaterial: recipientSigning,
    });
    const umk = crypto.getRandomValues(new Uint8Array(32));
    const delivery = createInitialAkeUmkDelivery({
      umk,
      userId,
      senderDeviceId,
      senderEncryptionKeyId: "sender-encryption-key-id",
      recipientDeviceId,
      recipientEncryptionKeyId: "recipient-encryption-key-id",
      responderPrekey: prekey.record,
      responderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(recipientSigning),
      senderSigningPrivateKeyMaterial: senderSigning,
      resourceHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      keyCheckpointHash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      keyEventHeadHash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      pendingRegistrationBindingHash: "pending-binding-hash",
    });

    expect(
      openInitialAkeUmkDelivery({
        ...delivery,
        privatePrekey: prekey.privatePrekey,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
      }),
    ).toEqual(umk);

    const wrongConfirmationHashDelivery = structuredClone(delivery.initialKeyDelivery);
    (wrongConfirmationHashDelivery.metadata as Record<string, unknown>).key_confirmation_hash =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(() =>
      openInitialAkeUmkDelivery({
        initialAke: delivery.initialAke,
        initialKeyDelivery: wrongConfirmationHashDelivery,
        privatePrekey: prekey.privatePrekey,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
      }),
    ).toThrow("initial_delivery_key_confirmation_hash_mismatch");

    const tamperedDelivery = structuredClone(delivery.initialKeyDelivery);
    (tamperedDelivery.metadata as Record<string, unknown>).recipient_device_id =
      crypto.randomUUID();
    expect(() =>
      openInitialAkeUmkDelivery({
        initialAke: delivery.initialAke,
        initialKeyDelivery: tamperedDelivery,
        privatePrekey: prekey.privatePrekey,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
      }),
    ).toThrow();
  });

  it("supports KEK initial and trust transfer delivery variants", () => {
    const userId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientSigning = generateHybridSigningPrivateKeyMaterial("device", recipientDeviceId);
    const senderPublic = publicKeyMaterialFromPrivate(senderSigning);
    const recipientPublic = publicKeyMaterialFromPrivate(recipientSigning);
    const kekPrekey = generateInitialAkeResponderPrekey({
      purpose: "device_approval_kek_initial",
      operationId: `${recipientDeviceId}:kek`,
      userId,
      deviceId: recipientDeviceId,
      issuedAtEventSequence: 1,
      expiresEventSequence: 2,
      signingPrivateKeyMaterial: recipientSigning,
    });
    const trustPrekey = generateInitialAkeResponderPrekey({
      purpose: "trust_transfer",
      operationId: `${recipientDeviceId}:trust`,
      userId,
      deviceId: recipientDeviceId,
      issuedAtEventSequence: 1,
      expiresEventSequence: 2,
      signingPrivateKeyMaterial: recipientSigning,
    });
    const kek = crypto.getRandomValues(new Uint8Array(32));
    const kekDelivery = createInitialAkeKekDelivery({
      kek,
      workspaceId: crypto.randomUUID(),
      keyVersion: 1,
      userId,
      senderDeviceId,
      senderEncryptionKeyId: "sender-encryption-key-id",
      recipientDeviceId,
      recipientEncryptionKeyId: "recipient-encryption-key-id",
      responderPrekey: kekPrekey.record,
      responderSigningPublicKeyMaterial: recipientPublic,
      senderSigningPrivateKeyMaterial: senderSigning,
      resourceHash: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      keyCheckpointHash: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
      keyEventHeadHash: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
      userCheckpointHash: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
      workspaceCheckpointHash: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
      workspaceEventHeadHash: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
      pendingRegistrationBindingHash: "pending-binding-hash",
    });
    expect(
      openInitialAkeUmkDelivery({
        ...kekDelivery,
        privatePrekey: kekPrekey.privatePrekey,
        senderSigningPublicKeyMaterial: senderPublic,
      }),
    ).toEqual(kek);

    const bundle = { protocol: "refmd.test.device-state-transfer", version: 1, user_id: userId };
    const trustDelivery = createInitialAkeDeviceStateTransferDelivery({
      deviceStateBundle: bundle,
      userId,
      senderDeviceId,
      senderEncryptionKeyId: "sender-encryption-key-id",
      recipientDeviceId,
      recipientEncryptionKeyId: "recipient-encryption-key-id",
      responderPrekey: trustPrekey.record,
      responderSigningPublicKeyMaterial: recipientPublic,
      senderSigningPrivateKeyMaterial: senderSigning,
      resourceHash: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
      keyCheckpointHash: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      keyEventHeadHash: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      workspacePinsHash: "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
      documentRollbackPinSetHash: "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",
      pendingRegistrationBindingHash: "pending-binding-hash",
    });
    expect(
      JSON.parse(
        new TextDecoder().decode(
          openInitialAkeUmkDelivery({
            ...trustDelivery,
            privatePrekey: trustPrekey.privatePrekey,
            senderSigningPublicKeyMaterial: senderPublic,
          }),
        ),
      ),
    ).toEqual(bundle);
  });
});
