import { describe, expect, it } from "vite-plus/test";
import { assertShareParticipantCheckpointAdvance } from "./signatures";
import { eventHash } from "./primitives";
import type { SignedKeyDirectoryEnvelope } from "./types";

const shareSigner = {
  signer_kind: "share_participant_device",
  share_id: "share-1",
  share_participant_principal_id: "principal-1",
  share_participant_device_id: "participant-device-1",
  signing_key_id: "share-signing-key",
};

const otherShareSigner = {
  ...shareSigner,
  share_participant_device_id: "participant-device-2",
  signing_key_id: "other-share-signing-key",
};

const deviceSigner = {
  signer_kind: "device",
  user_id: "user-1",
  device_id: "device-1",
  signing_key_id: "device-signing-key",
};

const previousPayload = {
  covered_event_head: {
    head_hash: "previous-event-hash",
    head_sequence: 1,
  },
  device_keys: [],
  identity_keys: [],
  revoked_key_ids: [],
  share_participant_keys: [{ key_id: shareSigner.signing_key_id }],
};

function checkpointEnvelope(coveredEvent: SignedKeyDirectoryEnvelope): SignedKeyDirectoryEnvelope {
  const state = {
    covered_event_head: {
      head_hash: eventHash(coveredEvent),
      head_sequence: coveredEvent.payload.sequence,
    },
    device_keys: [],
    identity_keys: [],
    revoked_key_ids: [],
    share_participant_keys: [{ key_id: shareSigner.signing_key_id }],
  };
  return {
    payload: state,
    signatures: [{ signature: {}, signer: shareSigner }],
  } as unknown as SignedKeyDirectoryEnvelope;
}

function eventEnvelope(
  eventType: string,
  signer: Record<string, unknown>,
  sequence = 2,
  previousEventHash = "previous-event-hash",
): SignedKeyDirectoryEnvelope {
  return {
    payload: {
      event_type: eventType,
      previous_event_hash: previousEventHash,
      sequence,
    },
    signatures: [{ signature: {}, signer }],
  } as unknown as SignedKeyDirectoryEnvelope;
}

describe("assertShareParticipantCheckpointAdvance", () => {
  it("allows an exact share-participant-signed covered document operation event", () => {
    const coveredEvent = eventEnvelope("document_write_session_admitted", shareSigner);
    const checkpoint = checkpointEnvelope(coveredEvent);

    expect(() =>
      assertShareParticipantCheckpointAdvance(checkpoint, [coveredEvent], previousPayload),
    ).not.toThrow();
  });

  it("rejects a device-signed covered document operation event", () => {
    const coveredEvent = eventEnvelope("document_write_session_admitted", deviceSigner);
    const checkpoint = checkpointEnvelope(coveredEvent);

    expect(() =>
      assertShareParticipantCheckpointAdvance(checkpoint, [coveredEvent], previousPayload),
    ).toThrow("share_participant_checkpoint_signer_missing");
  });

  it("rejects mixed document operation events under one share participant checkpoint", () => {
    const deviceEvent = eventEnvelope("document_write_session_admitted", deviceSigner, 2);
    const shareEvent = eventEnvelope(
      "document_update_accepted",
      shareSigner,
      3,
      eventHash(deviceEvent),
    );
    const checkpoint = checkpointEnvelope(shareEvent);

    expect(() =>
      assertShareParticipantCheckpointAdvance(
        checkpoint,
        [deviceEvent, shareEvent],
        previousPayload,
      ),
    ).toThrow("share_participant_checkpoint_scope_invalid");
  });

  it("rejects document operation events from a different share participant signer", () => {
    const coveredEvent = eventEnvelope("document_update_accepted", otherShareSigner);
    const checkpoint = checkpointEnvelope(coveredEvent);

    expect(() =>
      assertShareParticipantCheckpointAdvance(checkpoint, [coveredEvent], previousPayload),
    ).toThrow("share_participant_checkpoint_signer_mismatch");
  });
});
