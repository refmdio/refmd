import { describe, expect, it } from "vite-plus/test";
import {
  beginInitialAkeUmkDelivery,
  beginInitialAkeKekDelivery,
  beginInitialAkeDeviceStateTransferDelivery,
  finalizeInitialAkeDelivery,
  generateInitialAkeResponderPrekey,
  openInitialAkeUmkDelivery,
  respondToInitialAkeOffer,
} from "./initial-ake";
import {
  computeSigningKeyId,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
} from "./signature";
import { clearState, createInitialState } from "./worker/state";
import {
  handleFinalizeInitialAkeDelivery,
  handleOpenInitialAkeUmkDelivery,
  handleRespondToInitialAkeOffer,
} from "./worker/handler/kek";

const SERVER_CHALLENGE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

describe("Initial AKE UMK delivery", () => {
  it.each([
    ["missing challenge", ""],
    ["non-canonical challenge", `${SERVER_CHALLENGE}=`],
    ["31-byte challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    ["33-byte challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
  ])("rejects a %s before generating responder key material", (_name, serverChallenge) => {
    const deviceId = crypto.randomUUID();
    const signing = generateHybridSigningPrivateKeyMaterial("device", deviceId);

    expect(() =>
      generateInitialAkeResponderPrekey({
        purpose: "umk_distribution",
        operationId: crypto.randomUUID(),
        userId: crypto.randomUUID(),
        deviceId,
        serverChallenge,
        issuedAtMs: 1_700_000_000_000,
        expiresAtMs: 1_700_000_300_000,
        signingPrivateKeyMaterial: signing,
      }),
    ).toThrow();
  });

  it("rejects an unlisted responder prekey purpose", () => {
    const deviceId = crypto.randomUUID();
    const signing = generateHybridSigningPrivateKeyMaterial("device", deviceId);

    expect(() =>
      generateInitialAkeResponderPrekey({
        purpose: "legacy_distribution" as never,
        operationId: crypto.randomUUID(),
        userId: crypto.randomUUID(),
        deviceId,
        serverChallenge: SERVER_CHALLENGE,
        issuedAtMs: 1_700_000_000_000,
        expiresAtMs: 1_700_000_300_000,
        signingPrivateKeyMaterial: signing,
      }),
    ).toThrow("responder_prekey_purpose_invalid");
  });

  it("consumes the responder prekey at the worker boundary and rejects replay", () => {
    const userId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const operationId = recipientDeviceId;
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientSigning = generateHybridSigningPrivateKeyMaterial("device", recipientDeviceId);
    const prekey = generateInitialAkeResponderPrekey({
      purpose: "umk_distribution",
      operationId,
      userId,
      deviceId: recipientDeviceId,
      serverChallenge: SERVER_CHALLENGE,
      issuedAtMs: 1_700_000_000_000,
      expiresAtMs: 1_700_000_300_000,
      signingPrivateKeyMaterial: recipientSigning,
    });
    const started = beginInitialAkeUmkDelivery({
      umk: crypto.getRandomValues(new Uint8Array(32)),
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
    const state = createInitialState();
    state.initialAkeResponderPrekeys.set(
      `umk_distribution:${operationId}:${prekey.privatePrekey.prekey_id}`,
      prekey.privatePrekey,
    );
    const response = handleRespondToInitialAkeOffer(state, {
      offer: started.offer,
      senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
    });
    expect(state.initialAkeResponderPrekeys.size).toBe(0);
    expect(state.initialAkeResponderSessions.has(started.offer.transcript_hash)).toBe(true);
    expect(() =>
      handleRespondToInitialAkeOffer(state, {
        offer: started.offer,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
      }),
    ).toThrow("initial_ake_responder_prekey_missing");
    const delivery = finalizeInitialAkeDelivery({
      initiatorState: started.initiatorState,
      response: response as ReturnType<typeof respondToInitialAkeOffer>["response"],
      senderSigningPrivateKeyMaterial: senderSigning,
    });
    const payload = {
      ...delivery,
      senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
    };
    const responderSecret = state.initialAkeResponderSessions.get(
      started.offer.transcript_hash,
    )!.secret;

    expect(handleOpenInitialAkeUmkDelivery(state, payload)).toEqual({ status: "ok" });
    expect(responderSecret.every((byte) => byte === 0)).toBe(true);
    expect(state.initialAkeResponderSessions.size).toBe(0);
    expect(() => handleOpenInitialAkeUmkDelivery(state, payload)).toThrow(
      "initial_ake_responder_session_missing",
    );
  });

  it("requires an independently generated responder confirmation", () => {
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
      serverChallenge: SERVER_CHALLENGE,
      issuedAtMs: 1_700_000_000_000,
      expiresAtMs: 1_700_000_300_000,
      signingPrivateKeyMaterial: recipientSigning,
    });
    const started = beginInitialAkeUmkDelivery({
      umk: crypto.getRandomValues(new Uint8Array(32)),
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

    expect(started.offer).not.toHaveProperty("responder_confirmation");
    const reflectedResponse = {
      protocol: "refmd.initial-ake-responder-confirmation" as const,
      version: 1 as const,
      purpose: "umk_distribution" as const,
      transcript_hash: started.offer.transcript_hash,
      prekey_id: prekey.privatePrekey.prekey_id,
      responder_confirmation: started.offer.initiator_confirmation,
    };
    expect(() =>
      finalizeInitialAkeDelivery({
        initiatorState: started.initiatorState,
        response: reflectedResponse,
        senderSigningPrivateKeyMaterial: senderSigning,
      }),
    ).toThrow("initial_ake_responder_confirmation_invalid");
    expect(started.initiatorState.secret.every((byte) => byte === 0)).toBe(true);
  });

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
      serverChallenge: SERVER_CHALLENGE,
      issuedAtMs: 1_700_000_000_000,
      expiresAtMs: 1_700_000_300_000,
      signingPrivateKeyMaterial: recipientSigning,
    });
    const umk = crypto.getRandomValues(new Uint8Array(32));
    const started = beginInitialAkeUmkDelivery({
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

    const answered = respondToInitialAkeOffer({
      offer: started.offer,
      privatePrekey: prekey.privatePrekey,
      senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
    });
    const delivery = finalizeInitialAkeDelivery({
      initiatorState: started.initiatorState,
      response: answered.response,
      senderSigningPrivateKeyMaterial: senderSigning,
    });
    expect(
      openInitialAkeUmkDelivery({
        ...delivery,
        responderState: answered.responderState,
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
        responderState: answered.responderState,
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
        responderState: answered.responderState,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
      }),
    ).toThrow();
  });

  it("consumes and zeroes responder prekeys when initiator confirmation is malformed", () => {
    const exchange = createUmkExchange();
    const state = createInitialState();
    const prekeyStateKey = `umk_distribution:${exchange.operationId}:${exchange.prekey.privatePrekey.prekey_id}`;
    state.initialAkeResponderPrekeys.set(prekeyStateKey, exchange.prekey.privatePrekey);
    const malformedOffer = structuredClone(exchange.started.offer);
    malformedOffer.initiator_confirmation = "malformed";

    expect(() =>
      handleRespondToInitialAkeOffer(state, {
        offer: malformedOffer,
        senderSigningPublicKeyMaterial: exchange.senderPublic,
      }),
    ).toThrow();
    expect(state.initialAkeResponderPrekeys.size).toBe(0);
    expect(state.initialAkeResponderSessions.size).toBe(0);
    expect(exchange.prekey.privatePrekey.x25519_private.every((byte) => byte === 0)).toBe(true);
    expect(exchange.prekey.privatePrekey.mlkem768_private.every((byte) => byte === 0)).toBe(true);
  });

  it("zeroes responder prekeys during worker lifecycle cleanup", () => {
    const exchange = createUmkExchange();
    const state = createInitialState();
    state.initialAkeResponderPrekeys.set("pending", exchange.prekey.privatePrekey);
    const answered = respondToInitialAkeOffer({
      offer: exchange.started.offer,
      privatePrekey: exchange.prekey.privatePrekey,
      senderSigningPublicKeyMaterial: exchange.senderPublic,
    });
    state.initialAkeResponderSessions.set(
      exchange.started.offer.transcript_hash,
      answered.responderState,
    );

    clearState(state);

    expect(exchange.prekey.privatePrekey.x25519_private.every((byte) => byte === 0)).toBe(true);
    expect(exchange.prekey.privatePrekey.mlkem768_private.every((byte) => byte === 0)).toBe(true);
    expect(state.initialAkeResponderPrekeys.size).toBe(0);
    expect(answered.responderState.secret.every((byte) => byte === 0)).toBe(true);
    expect(state.initialAkeResponderSessions.size).toBe(0);
  });

  it("consumes and zeroes the responder session when final delivery opening fails", () => {
    const exchange = createUmkExchange();
    const state = createInitialState();
    state.initialAkeResponderPrekeys.set(
      `umk_distribution:${exchange.operationId}:${exchange.prekey.privatePrekey.prekey_id}`,
      exchange.prekey.privatePrekey,
    );
    const response = handleRespondToInitialAkeOffer(state, {
      offer: exchange.started.offer,
      senderSigningPublicKeyMaterial: exchange.senderPublic,
    });
    const delivery = finalizeInitialAkeDelivery({
      initiatorState: exchange.started.initiatorState,
      response: response as ReturnType<typeof respondToInitialAkeOffer>["response"],
      senderSigningPrivateKeyMaterial: exchange.senderSigning,
    });
    const responderSecret = state.initialAkeResponderSessions.get(
      exchange.started.offer.transcript_hash,
    )!.secret;
    responderSecret.set(crypto.getRandomValues(new Uint8Array(responderSecret.length)));

    expect(() =>
      handleOpenInitialAkeUmkDelivery(state, {
        ...delivery,
        senderSigningPublicKeyMaterial: exchange.senderPublic,
      }),
    ).toThrow();
    expect(responderSecret.every((byte) => byte === 0)).toBe(true);
    expect(state.initialAkeResponderSessions.size).toBe(0);
  });

  it("rejects replay of a consumed responder confirmation", () => {
    const exchange = createUmkExchange();
    const answered = respondToInitialAkeOffer({
      offer: exchange.started.offer,
      privatePrekey: exchange.prekey.privatePrekey,
      senderSigningPublicKeyMaterial: exchange.senderPublic,
    });
    const state = createInitialState();
    state.deviceHybridSigningState = {
      privateKeyMaterial: exchange.senderSigning,
      publicKeyMaterial: exchange.senderPublic,
      signingKeyId: computeSigningKeyId(exchange.senderPublic),
    };
    state.initialAkeInitiatorSessions.set(
      exchange.started.offer.transcript_hash,
      exchange.started.initiatorState,
    );

    expect(handleFinalizeInitialAkeDelivery(state, { response: answered.response })).toHaveProperty(
      "initialKeyDelivery",
    );
    expect(state.initialAkeInitiatorSessions.size).toBe(0);
    expect(() => handleFinalizeInitialAkeDelivery(state, { response: answered.response })).toThrow(
      "initial_ake_initiator_session_missing",
    );
    answered.responderState.secret.fill(0);
  });

  it("zeroes the initiator secret for malformed or mismatched responder confirmations", () => {
    for (const mutate of [
      (response: Record<string, unknown>) => delete response.responder_confirmation,
      (response: Record<string, unknown>) => {
        response.responder_confirmation = "malformed";
      },
      (response: Record<string, unknown>) => {
        response.purpose = "trust_transfer";
      },
      (response: Record<string, unknown>) => {
        response.transcript_hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      },
      (response: Record<string, unknown>) => {
        response.prekey_id = crypto.randomUUID();
      },
    ]) {
      const exchange = createUmkExchange();
      const answered = respondToInitialAkeOffer({
        offer: exchange.started.offer,
        privatePrekey: exchange.prekey.privatePrekey,
        senderSigningPublicKeyMaterial: exchange.senderPublic,
      });
      const response = structuredClone(answered.response) as unknown as Record<string, unknown>;
      mutate(response);

      expect(() =>
        finalizeInitialAkeDelivery({
          initiatorState: exchange.started.initiatorState,
          response: response as never,
          senderSigningPrivateKeyMaterial: exchange.senderSigning,
        }),
      ).toThrow();
      expect(exchange.started.initiatorState.secret.every((byte) => byte === 0)).toBe(true);
      answered.responderState.secret.fill(0);
    }
  });

  it("rejects purpose, operation, and transcript substitution before responding", () => {
    for (const mutate of [
      (offer: Record<string, unknown>) => {
        offer.purpose = "trust_transfer";
      },
      (offer: Record<string, unknown>) => {
        (offer.transcript as Record<string, unknown>).purpose = "trust_transfer";
      },
      (offer: Record<string, unknown>) => {
        const transcript = offer.transcript as Record<string, unknown>;
        (transcript.context as Record<string, unknown>).operation_id = crypto.randomUUID();
      },
    ]) {
      const exchange = createUmkExchange();
      const offer = structuredClone(exchange.started.offer) as unknown as Record<string, unknown>;
      mutate(offer);

      expect(() =>
        respondToInitialAkeOffer({
          offer: offer as never,
          privatePrekey: exchange.prekey.privatePrekey,
          senderSigningPublicKeyMaterial: exchange.senderPublic,
        }),
      ).toThrow();
      exchange.started.initiatorState.secret.fill(0);
      exchange.prekey.privatePrekey.x25519_private.fill(0);
      exchange.prekey.privatePrekey.mlkem768_private.fill(0);
    }
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
      serverChallenge: SERVER_CHALLENGE,
      issuedAtMs: 1_700_000_000_000,
      expiresAtMs: 1_700_000_300_000,
      signingPrivateKeyMaterial: recipientSigning,
    });
    const trustPrekey = generateInitialAkeResponderPrekey({
      purpose: "trust_transfer",
      operationId: `${recipientDeviceId}:trust`,
      userId,
      deviceId: recipientDeviceId,
      serverChallenge: SERVER_CHALLENGE,
      issuedAtMs: 1_700_000_000_000,
      expiresAtMs: 1_700_000_300_000,
      signingPrivateKeyMaterial: recipientSigning,
    });
    const kek = crypto.getRandomValues(new Uint8Array(32));
    const kekStarted = beginInitialAkeKekDelivery({
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
    const kekAnswered = respondToInitialAkeOffer({
      offer: kekStarted.offer,
      privatePrekey: kekPrekey.privatePrekey,
      senderSigningPublicKeyMaterial: senderPublic,
    });
    const kekDelivery = finalizeInitialAkeDelivery({
      initiatorState: kekStarted.initiatorState,
      response: kekAnswered.response,
      senderSigningPrivateKeyMaterial: senderSigning,
    });
    expect(
      openInitialAkeUmkDelivery({
        ...kekDelivery,
        responderState: kekAnswered.responderState,
        senderSigningPublicKeyMaterial: senderPublic,
      }),
    ).toEqual(kek);

    const bundle = { protocol: "refmd.test.device-state-transfer", version: 1, user_id: userId };
    const trustStarted = beginInitialAkeDeviceStateTransferDelivery({
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
      transferScopeHash: "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ",
      auditCheckpointPinSetHash: "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK",
      pendingRegistrationBindingHash: "pending-binding-hash",
    });
    const trustAnswered = respondToInitialAkeOffer({
      offer: trustStarted.offer,
      privatePrekey: trustPrekey.privatePrekey,
      senderSigningPublicKeyMaterial: senderPublic,
    });
    const trustDelivery = finalizeInitialAkeDelivery({
      initiatorState: trustStarted.initiatorState,
      response: trustAnswered.response,
      senderSigningPrivateKeyMaterial: senderSigning,
    });
    expect(
      JSON.parse(
        new TextDecoder().decode(
          openInitialAkeUmkDelivery({
            ...trustDelivery,
            responderState: trustAnswered.responderState,
            senderSigningPublicKeyMaterial: senderPublic,
          }),
        ),
      ),
    ).toEqual(bundle);
  });
});

function createUmkExchange() {
  const userId = crypto.randomUUID();
  const senderDeviceId = crypto.randomUUID();
  const recipientDeviceId = crypto.randomUUID();
  const operationId = recipientDeviceId;
  const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
  const recipientSigning = generateHybridSigningPrivateKeyMaterial("device", recipientDeviceId);
  const senderPublic = publicKeyMaterialFromPrivate(senderSigning);
  const prekey = generateInitialAkeResponderPrekey({
    purpose: "umk_distribution",
    operationId,
    userId,
    deviceId: recipientDeviceId,
    serverChallenge: SERVER_CHALLENGE,
    issuedAtMs: 1_700_000_000_000,
    expiresAtMs: 1_700_000_300_000,
    signingPrivateKeyMaterial: recipientSigning,
  });
  const started = beginInitialAkeUmkDelivery({
    umk: crypto.getRandomValues(new Uint8Array(32)),
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
  return { operationId, senderSigning, senderPublic, prekey, started };
}
