import { encodeAwarenessUpdate } from "y-protocols/awareness";
import type { DocumentState } from "../../../model/document-state/types";
import { encodeEphemeralPayload, MSG_MESSAGE } from "./session";
import { sendEphemeralEnvelope } from "./send";

export function setupAwarenessRelay(
  state: DocumentState,
  documentId: string,
  deviceId: string,
  signingPubKeyB64: string,
): void {
  state.awarenessRelayCleanup?.();

  let throttleTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingClients: number[] | null = null;

  const flush = () => {
    throttleTimer = null;
    const clients = pendingClients;
    pendingClients = null;
    if (!clients?.length) return;
    const session = state.ephemeralSession;
    if (!session || !state.channel) return;
    if (session.trustedPeers.size === 0) return;
    const encoded = encodeAwarenessUpdate(state.awareness, clients);
    const payload = encodeEphemeralPayload(session, MSG_MESSAGE, encoded);
    sendEphemeralEnvelope(payload, documentId, state.keyVersion, deviceId, signingPubKeyB64).catch(
      () => {},
    );
  };

  const onUpdate = (
    { added, updated, removed }: { added: number[]; updated: number[]; removed: number[] },
    origin: unknown,
  ) => {
    if (origin === "remote" || origin === "same-user") return;
    const localId = state.awareness.clientID;
    const changed = [...added, ...updated, ...removed].filter((id) => id === localId);
    if (!changed.length) return;

    if (!pendingClients) {
      pendingClients = changed;
    } else {
      for (const c of changed) {
        if (!pendingClients.includes(c)) pendingClients.push(c);
      }
    }
    if (!throttleTimer) {
      throttleTimer = setTimeout(flush, 100);
    }
  };

  state.awareness.on("update", onUpdate);
  state.awarenessRelayCleanup = () => {
    if (throttleTimer) {
      clearTimeout(throttleTimer);
      throttleTimer = null;
    }
    pendingClients = null;
    state.awareness.off("update", onUpdate);
  };
}
