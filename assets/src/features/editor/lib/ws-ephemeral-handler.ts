import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { deviceState } from "@/shared/lib/auth-state";
import { resolveSigningKey } from "./document-verification";
import type { DocumentState } from "./document-state-cache";
import {
  decodeEphemeralPayload,
  handleIncomingEphemeral,
  encodeEphemeralPayload,
  MSG_MESSAGE,
} from "./ephemeral-session";
import { sendEphemeralEnvelope } from "./ephemeral-send";
import { assignUserColor } from "./user-colors";
import {
  encodeAwarenessUpdate,
  applyAwarenessUpdate,
  removeAwarenessStates,
} from "y-protocols/awareness";

// ── Ephemeral message handling ────────────────────────────────

export function handleEphemeralMessage(
  payload: Record<string, unknown>,
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): void {
  processEphemeral(payload, state, documentId, localDeviceSigningPubKey, failClosed).catch(
    (err) => {
      console.warn("[ws] Ephemeral processing error:", err);
    },
  );
}

async function processEphemeral(
  payload: Record<string, unknown>,
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): Promise<void> {
  const device = deviceState();
  if (!device || !state.ephemeralSession) return;

  const pd = payload.publicData as Record<string, unknown> | undefined;
  const senderPubKeyB64 = pd?.signingPubKey as string | undefined;
  if (!senderPubKeyB64 || !pd) return;

  if (pd.docId !== documentId) return;

  // Same device (same signingPubKey): skip. This covers both own broadcasts
  // (server uses broadcast_from) and same-device other-tab broadcasts.
  // Design: awareness is per-device, not per-tab. Same-device tabs share
  // the same user identity and don't need mutual cursor visibility.
  if (senderPubKeyB64 === localDeviceSigningPubKey) return;

  const resolveResult = await resolveSigningKey(senderPubKeyB64, state);
  if (resolveResult.status === "key_changed") {
    failClosed("verification_failed");
    return;
  }
  if (resolveResult.status === "not_found") {
    failClosed("verification_failed");
    return;
  }
  if (state.revokedSigningKeys.has(senderPubKeyB64)) return;
  const senderPubKeyBytes = resolveResult.key;

  const worker = getCryptoWorker();

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
    });
  } catch {
    return;
  }

  const decoded = decodeEphemeralPayload(decrypted);
  if (!decoded) return;

  const result = await handleIncomingEphemeral(
    state.ephemeralSession,
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
        device.deviceId,
        localDeviceSigningPubKey!,
      );
      if (state.ephemeralSession?.trustedPeers.has(remoteSessionIdB64)) {
        await resendAwareness(state, documentId, device.deviceId, localDeviceSigningPubKey!);
      }
      break;
    case "trusted":
      await resendAwareness(state, documentId, device.deviceId, localDeviceSigningPubKey!);
      break;
    case "awareness": {
      // Track which clientIDs are added/updated/removed
      let changedClients: number[] = [];
      let removedClients: number[] = [];
      const captureChange = ({
        added,
        updated,
        removed,
      }: {
        added: number[];
        updated: number[];
        removed: number[];
      }) => {
        changedClients = [...added, ...updated];
        removedClients = [...removed];
      };

      // Pre-check ownership: save legitimate owner states + meta before apply so
      // hijacking reverts both state and clock/timeout metadata.
      const savedStates = new Map<number, Record<string, unknown>>();
      const savedMeta = new Map<number, { clock: number; lastUpdated: number }>();
      const states = state.awareness.getStates();
      const meta = (state.awareness as any).meta as Map<
        number,
        { clock: number; lastUpdated: number }
      >;
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
        if (event === "update") originalEmit(event, args);
      };
      state.awareness.on("update", captureChange);
      try {
        applyAwarenessUpdate(state.awareness, result.awarenessData, "remote");
      } finally {
        state.awareness.off("update", captureChange);
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

export function handlePeerLeft(payload: Record<string, unknown>, state: DocumentState): void {
  const signingPubKey = payload.signingPubKey as string | undefined;
  if (!signingPubKey) return;

  // Server broadcasts peer-left only after delayed Presence recheck confirms
  // the device has no remaining connections. Trust the server's judgment.
  const toRemove: number[] = [];
  const localId = state.awareness.clientID;
  state.awareness.getStates().forEach((awarenessState, clientId) => {
    if (clientId === localId) return;
    const user = awarenessState.user as { signingPubKey?: string } | undefined;
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

export async function resendAwareness(
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
  await sendEphemeralEnvelope(payload, documentId, state.keyVersion, deviceId, signingPubKeyB64);
}
