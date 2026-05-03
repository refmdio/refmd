import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { deviceState } from "@/entities/session";
import { resolveSigningKey } from "../inbound/signing-keys";
import type { DocumentState } from "../../../model/document-state/types";
import {
  decodeEphemeralPayload,
  handleIncomingEphemeral,
  encodeEphemeralPayload,
  MSG_MESSAGE,
} from "./session";
import { sendEphemeralEnvelope } from "./send";
import { assignUserColor } from "../../user-colors";
import { getDocumentDekCacheKey } from "../share-access";
import {
  encodeAwarenessUpdate,
  applyAwarenessUpdate,
  removeAwarenessStates,
} from "y-protocols/awareness";
import type { EphemeralPayload, PeerLeftPayload } from "@/shared/lib/ws/document-payloads";
import { getLocalDeviceId } from "../share-identity";
import { getDocumentCryptoWorker } from "../crypto-worker";
// ── Ephemeral message handling ────────────────────────────────
export function handleEphemeralMessage(
  payload: EphemeralPayload,
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey: string | undefined,
): void {
  processEphemeral(payload, state, documentId, localDeviceSigningPubKey).catch((err) => {
    console.warn("[ws] Ephemeral processing error:", err);
  });
}
async function processEphemeral(
  payload: EphemeralPayload,
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey: string | undefined,
): Promise<void> {
  const device = deviceState();
  const localDeviceId = getLocalDeviceId(state) ?? device?.deviceId ?? null;
  const session = state.ephemeralSession;
  if (!localDeviceId || !session) return;
  const pd = payload.publicData;
  const senderPubKeyB64 = pd.signingPubKey;
  if (!senderPubKeyB64 || !pd) return;
  if (pd.docId !== documentId) return;
  // Same device (same signingPubKey): skip. This covers both own broadcasts
  // (server uses broadcast_from) and same-device other-tab broadcasts.
  // Awareness is per-device, not per-tab; same-device tabs share identity
  // and don't need mutual cursor visibility.
  if (senderPubKeyB64 === localDeviceSigningPubKey) return;
  const resolveResult = await resolveSigningKey(senderPubKeyB64, state);
  if (resolveResult.status === "key_changed") {
    return;
  }
  if (resolveResult.status === "not_found") {
    return;
  }
  if (state.revokedSigningKeys.has(senderPubKeyB64)) return;
  const senderPubKeyBytes = resolveResult.key;
  const worker = getDocumentCryptoWorker(state);
  const valid = await worker.verifyWsSignature({
    prefix: "refmd_ephemeral",
    ciphertext: payload.ciphertext as string,
    nonce: payload.nonce as string,
    publicData: pd,
    signature: base64UrlDecode(payload.signature as string),
    signingPubKey: senderPubKeyBytes,
  });
  if (!valid) return;
  let decrypted: Uint8Array;
  try {
    decrypted = await worker.decryptContent({
      ciphertext: base64UrlDecode(payload.ciphertext as string),
      nonce: base64UrlDecode(payload.nonce as string),
      documentId,
      keyVersion: state.keyVersion,
      cacheKey: getDocumentDekCacheKey(state, documentId),
    });
  } catch {
    return;
  }
  const decoded = decodeEphemeralPayload(decrypted);
  if (!decoded) return;
  if (state.ephemeralSession !== session) return;
  const result = await handleIncomingEphemeral(
    session,
    decoded,
    senderPubKeyB64,
    senderPubKeyBytes,
    worker,
  );
  const remoteSessionIdB64 = base64UrlEncode(decoded.sessionId);
  switch (result.action) {
    case "respond":
      await sendEphemeralEnvelope(
        result.responsePayload,
        documentId,
        state.keyVersion,
        localDeviceId,
        localDeviceSigningPubKey!,
        state.stateKey,
        getDocumentDekCacheKey(state, documentId),
        worker,
      );
      if (state.ephemeralSession?.trustedPeers.has(remoteSessionIdB64)) {
        await resendAwareness(state, documentId, localDeviceId, localDeviceSigningPubKey!);
      }
      break;
    case "trusted":
      await resendAwareness(state, documentId, localDeviceId, localDeviceSigningPubKey!);
      break;
    case "awareness": {
      // Track only semantic awareness changes. The lower-level "update"
      // event also fires for keepalives with unchanged state.
      let changedClients: number[] = [];
      let removedClients: number[] = [];
      const captureChange = (args: unknown[]) => {
        const change = args[0] as
          | {
              added: number[];
              updated: number[];
              removed: number[];
            }
          | undefined;
        if (!change) return;
        const { added, updated, removed } = change;
        changedClients = [...added, ...updated];
        removedClients = [...removed];
      };
      // Pre-check ownership: save legitimate owner states + meta before apply so
      // hijacking reverts both state and clock/timeout metadata.
      const savedStates = new Map<number, Record<string, unknown>>();
      const savedMeta = new Map<
        number,
        {
          clock: number;
          lastUpdated: number;
        }
      >();
      const states = state.awareness.getStates();
      const meta = state.awareness.meta;
      for (const [clientId, clientState] of states) {
        const existingOwner = state.awarenessClientOwners.get(clientId);
        if (existingOwner && existingOwner !== senderPubKeyB64) {
          savedStates.set(clientId, structuredClone(clientState));
          const m = meta.get(clientId);
          if (m) savedMeta.set(clientId, { ...m });
        }
      }
      // Suppress "change" events during apply — unverified data must not
      // be observable by UI consumers. Events are re-emitted after verification.
      const originalEmit = state.awareness.emit.bind(state.awareness);
      state.awareness.emit = (event: string, args: unknown[]) => {
        if (event === "change") {
          captureChange(args);
          return;
        }
        if (event === "update") originalEmit(event, args);
      };
      try {
        applyAwarenessUpdate(state.awareness, result.awarenessData, "remote");
      } finally {
        state.awareness.emit = originalEmit;
      }
      // Verify clientID ownership for removals: a peer can only remove its own clientIDs.
      // Restore illegitimate removals from the saved state.
      const illegitimateRemovals: number[] = [];
      for (const clientId of removedClients) {
        const owner = state.awarenessClientOwners.get(clientId);
        if (owner && owner !== senderPubKeyB64) {
          illegitimateRemovals.push(clientId);
        }
      }
      if (illegitimateRemovals.length > 0) {
        for (const clientId of illegitimateRemovals) {
          const saved = savedStates.get(clientId);
          if (saved) states.set(clientId, saved);
          const savedM = savedMeta.get(clientId);
          if (savedM) meta.set(clientId, savedM);
        }
        removedClients = removedClients.filter((id) => !illegitimateRemovals.includes(id));
      }
      // Verify clientID ownership for updates: each clientID must belong to the sender.
      // If a clientID was previously owned by a different signingPubKey, restore
      // the legitimate owner's state instead of removing it entirely.
      const hijackedClients: number[] = [];
      for (const clientId of changedClients) {
        const existingOwner = state.awarenessClientOwners.get(clientId);
        if (existingOwner && existingOwner !== senderPubKeyB64) {
          hijackedClients.push(clientId);
        } else {
          state.awarenessClientOwners.set(clientId, senderPubKeyB64);
        }
      }
      if (hijackedClients.length > 0) {
        for (const clientId of hijackedClients) {
          const saved = savedStates.get(clientId);
          if (saved) {
            states.set(clientId, saved);
            const savedM = savedMeta.get(clientId);
            if (savedM) meta.set(clientId, savedM);
          } else {
            removeAwarenessStates(state.awareness, [clientId], "ownership-violation");
          }
        }
        if (hijackedClients.length > 0) {
          state.awareness.emit("change", [
            {
              added: [],
              updated: hijackedClients.filter((id) => savedStates.has(id)),
              removed: [],
            },
            "ownership-restore",
          ]);
        }
        changedClients = changedClients.filter((id) => !hijackedClients.includes(id));
      }
      // Dedup: same signingPubKey should have at most one clientID (per-device granularity).
      // If a new clientID arrives from the same device, remove the old one.
      const staleForDevice: number[] = [];
      for (const clientId of changedClients) {
        for (const [existingId, owner] of state.awarenessClientOwners) {
          if (owner === senderPubKeyB64 && existingId !== clientId) {
            staleForDevice.push(existingId);
          }
        }
      }
      if (staleForDevice.length > 0) {
        removeAwarenessStates(state.awareness, staleForDevice, "device-dedup");
        for (const id of staleForDevice) {
          state.awarenessClientOwners.delete(id);
        }
      }
      // Override self-reported user fields with verified values to prevent impersonation.
      const verifiedUserId = state.signingKeyOwners.get(senderPubKeyB64);
      if (verifiedUserId) {
        const verifiedName = state.memberNames.get(verifiedUserId);
        const verifiedColor = assignUserColor(verifiedUserId, state.awareness);
        let needsReemit = false;
        for (const clientId of changedClients) {
          const awarenessState = state.awareness.getStates().get(clientId);
          if (awarenessState?.user) {
            if (awarenessState.user.userId !== verifiedUserId) {
              awarenessState.user.userId = verifiedUserId;
              needsReemit = true;
            }
            const safeName = verifiedName || verifiedUserId;
            if (awarenessState.user.name !== safeName) {
              awarenessState.user.name = safeName;
              needsReemit = true;
            }
            if (awarenessState.user.color !== verifiedColor) {
              awarenessState.user.color = verifiedColor;
              needsReemit = true;
            }
            if (awarenessState.user.signingPubKey !== senderPubKeyB64) {
              awarenessState.user.signingPubKey = senderPubKeyB64;
              needsReemit = true;
            }
          }
        }
        if (needsReemit) {
          state.awareness.emit("change", [
            { added: [], updated: changedClients, removed: removedClients },
            "userId-override",
          ]);
        } else if (changedClients.length > 0 || removedClients.length > 0) {
          state.awareness.emit("change", [
            { added: [], updated: changedClients, removed: removedClients },
            "verified-remote",
          ]);
        }
      } else if (changedClients.length > 0 || removedClients.length > 0) {
        state.awareness.emit("change", [
          { added: [], updated: changedClients, removed: removedClients },
          "verified-remote",
        ]);
      }
      break;
    }
    case "reject":
      break;
  }
}
export function handlePeerLeft(payload: PeerLeftPayload, state: DocumentState): void {
  const signingPubKey = payload.signingPubKey;
  if (!signingPubKey) return;
  // Server broadcasts peer-left only after delayed Presence recheck confirms
  // the device has no remaining connections. Trust the server's judgment.
  const toRemove: number[] = [];
  const localId = state.awareness.clientID;
  state.awareness.getStates().forEach((awarenessState, clientId) => {
    if (clientId === localId) return;
    const user = awarenessState.user as
      | {
          signingPubKey?: string;
        }
      | undefined;
    if (user?.signingPubKey === signingPubKey) {
      toRemove.push(clientId);
    }
  });
  if (toRemove.length > 0) {
    removeAwarenessStates(state.awareness, toRemove, "peer-left");
    for (const clientId of toRemove) {
      state.awarenessClientOwners.delete(clientId);
    }
  }
}
async function resendAwareness(
  state: DocumentState,
  documentId: string,
  deviceId: string,
  signingPubKeyB64: string,
): Promise<void> {
  const session = state.ephemeralSession;
  if (!session) return;
  const localState = state.awareness.getLocalState();
  if (!localState) return;
  const encoded = encodeAwarenessUpdate(state.awareness, [state.awareness.clientID]);
  const payload = encodeEphemeralPayload(session, MSG_MESSAGE, encoded);
  await sendEphemeralEnvelope(
    payload,
    documentId,
    state.keyVersion,
    deviceId,
    signingPubKeyB64,
    state.stateKey,
    getDocumentDekCacheKey(state, documentId),
    getDocumentCryptoWorker(state),
  );
}
