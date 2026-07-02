import { encodeAwarenessUpdate } from "y-protocols/awareness";
import { getChannelState } from "@/shared/lib/ws/phoenix-channel";
import type { DocumentState } from "../../model/document-state/types";
import { getDocumentDekCacheKey } from "./share-access";
import { encodeEphemeralPayload, MSG_MESSAGE } from "./ephemeral-session";
import { sendEphemeralEnvelope } from "./ephemeral-send";

export function setupAwarenessRelay(
  state: DocumentState,
  documentId: string,
  signingKeyId: string,
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
    if (getChannelState(state.channel) !== "joined") return;
    if (session.trustedPeers.size === 0) return;
    const encoded = encodeAwarenessUpdate(state.awareness, clients);
    const payload = encodeEphemeralPayload(session, MSG_MESSAGE, encoded);
    sendEphemeralEnvelope(
      payload,
      documentId,
      state,
      signingKeyId,
      state.stateKey,
      getDocumentDekCacheKey(state, documentId),
    ).catch(() => {});
  };

  const onChange = (
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

  state.awareness.on("change", onChange);
  state.awarenessRelayCleanup = () => {
    if (throttleTimer) {
      clearTimeout(throttleTimer);
      throttleTimer = null;
    }
    pendingClients = null;
    state.awareness.off("change", onChange);
  };
}
