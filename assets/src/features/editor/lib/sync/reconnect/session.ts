import { deviceState } from "@/entities/session";
import type { DocumentState } from "../../../model/document-state/types";
import { createEphemeralSession } from "../ephemeral/session";
import { setupAwarenessRelay } from "../ephemeral/awareness-relay";
import { sendInitialize } from "../bootstrap/post-init";
import { getLocalDeviceId } from "../share-identity";

export function runPostReconnectSession(
  state: DocumentState,
  documentId: string,
  deviceId: string,
  localDeviceSigningPubKey: string,
): void {
  const currentDevice = deviceState();
  const localDeviceId = getLocalDeviceId(state) ?? currentDevice?.deviceId ?? null;
  if (!localDeviceId || localDeviceId !== deviceId) return;

  const session = createEphemeralSession();
  state.ephemeralSession = session;
  sendInitialize(session, state, documentId, deviceId, localDeviceSigningPubKey);
  setupAwarenessRelay(state, documentId, deviceId, localDeviceSigningPubKey);
}
