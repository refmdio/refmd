import { Channel, type Socket } from "phoenix";
import {
  createPhoenixJoinError,
  disableChannelAutoRejoin,
  leavePhoenixChannel,
  notifyChannelClosedOnSocketClose,
  PhoenixChannelTransportError,
} from "./channel";
import {
  createTemporaryPhoenixSocket,
  ensurePhoenixWsToken,
  getOrCreatePhoenixSocket,
  isPhoenixSocketConnected,
  resetPhoenixSocketState,
} from "./socket";
import { getPreferredSessionScope } from "@/shared/lib/auth/session-scope";
import { recordAuthTransportNetworkFailure } from "./transport-coordinator";
import type {
  DocumentPayload,
  UpdatePayload,
  RemoteSnapshotPayload,
  UpdateSavedPayload,
  UpdateSaveFailedPayload,
  SnapshotSavedPayload,
  SnapshotSaveFailedPayload,
  EphemeralPayload,
  PeerLeftPayload,
  PublicStatusChangedPayload,
} from "./document-payloads";

export { isPhoenixJoinError, PhoenixChannelTransportError } from "./channel";

const channels = new Map<string, Channel>();
const channelDocumentIds = new Map<string, string>();
const channelScopes = new Map<string, "user" | "share">();
const channelJoinPromises = new Map<string, Promise<Channel>>();

function resolveChannelScope(scope?: "user" | "share"): "user" | "share" {
  return scope ?? (getPreferredSessionScope() === "share" ? "share" : "user");
}
export function getChannelState(channel: Channel): string {
  return channel.state;
}

export function hasTrackedDocumentChannel(documentId: string): boolean {
  for (const trackedDocumentId of channelDocumentIds.values()) {
    if (trackedDocumentId === documentId) return true;
  }
  return false;
}

export function isSocketConnected(target: Socket): boolean;
export function isSocketConnected(): boolean;
export function isSocketConnected(target?: Socket): boolean {
  return target !== undefined ? isPhoenixSocketConnected(target) : isPhoenixSocketConnected();
}
export interface DocumentChannelCallbacks {
  onDocument: (payload: DocumentPayload) => void;
  onUpdate: (payload: UpdatePayload) => void;
  onSnapshot: (payload: RemoteSnapshotPayload) => void;
  onUpdateSaved: (payload: UpdateSavedPayload) => void;
  onUpdateSaveFailed: (payload: UpdateSaveFailedPayload) => void;
  onSnapshotSaved: (payload: SnapshotSavedPayload) => void;
  onSnapshotSaveFailed: (payload: SnapshotSaveFailedPayload) => void;
  onEphemeralMessage: (payload: EphemeralPayload) => void;
  onPeerLeft: (payload: PeerLeftPayload) => void;
  onPublicStatusChanged: (payload: PublicStatusChangedPayload) => void;
  onUnauthorized: () => void;
  onError: (reason: unknown) => void;
  onClose: () => void;
}

export interface TemporaryDocumentChannelHandle {
  channel: Channel;
  dispose: () => void;
}

function configureDocumentChannel(
  sock: Socket,
  channel: Channel,
  callbacks: DocumentChannelCallbacks,
): void {
  // Disable Phoenix auto-rejoin BEFORE join(): PoP challenge is consumed on
  // first join, so auto-rejoin with stale params always fails.
  disableChannelAutoRejoin(channel);

  notifyChannelClosedOnSocketClose(sock, channel, callbacks.onClose);

  channel.on<DocumentPayload>("document", (payload) => callbacks.onDocument(payload));
  channel.on<UpdatePayload>("update", (payload) => callbacks.onUpdate(payload));
  channel.on<RemoteSnapshotPayload>("snapshot", (payload) => callbacks.onSnapshot(payload));
  channel.on<UpdateSavedPayload>("update-saved", (payload) => callbacks.onUpdateSaved(payload));
  channel.on<UpdateSaveFailedPayload>("update-save-failed", (payload) =>
    callbacks.onUpdateSaveFailed(payload),
  );
  channel.on<SnapshotSavedPayload>("snapshot-saved", (payload) =>
    callbacks.onSnapshotSaved(payload),
  );
  channel.on<SnapshotSaveFailedPayload>("snapshot-save-failed", (payload) =>
    callbacks.onSnapshotSaveFailed(payload),
  );
  channel.on<EphemeralPayload>("ephemeral-message", (payload) =>
    callbacks.onEphemeralMessage(payload),
  );
  channel.on<PeerLeftPayload>("peer-left", (payload) => callbacks.onPeerLeft(payload));
  channel.on<PublicStatusChangedPayload>("public-status-changed", (payload) =>
    callbacks.onPublicStatusChanged(payload),
  );
  channel.on("connection-cap-evict", () => callbacks.onError("connection_cap_evict"));
  channel.on("unauthorized", () => callbacks.onUnauthorized());
  channel.on("document-not-found", () => callbacks.onError("document_not_found"));
  channel.on("document-error", () => callbacks.onError("document_error"));
  channel.onError((reason) => callbacks.onError(reason ?? "connection_error"));
  channel.onClose(() => callbacks.onClose());
}

export async function joinDocument(
  documentId: string,
  params: Record<string, unknown>,
  callbacks: DocumentChannelCallbacks,
  channelKey = documentId,
  scope?: "user" | "share",
): Promise<Channel> {
  const channelScope = resolveChannelScope(scope);
  await ensurePhoenixWsToken(channelScope);

  const sock = getOrCreatePhoenixSocket(channelScope);
  const topic = `document:${documentId}`;
  const existing = channels.get(channelKey);
  if (existing && getChannelState(existing) === "joined") {
    return Promise.resolve(existing);
  }
  const pendingJoin = channelJoinPromises.get(channelKey);
  if (existing && pendingJoin && getChannelState(existing) === "joining") {
    return pendingJoin;
  }
  if (existing) {
    leavePhoenixChannel(existing);
    channels.delete(channelKey);
    channelDocumentIds.delete(channelKey);
    channelScopes.delete(channelKey);
    channelJoinPromises.delete(channelKey);
  }
  const channel = sock.channel(topic, params);
  configureDocumentChannel(sock, channel, callbacks);
  channels.set(channelKey, channel);
  channelDocumentIds.set(channelKey, documentId);
  channelScopes.set(channelKey, channelScope);
  const joinPromise = new Promise<Channel>((resolve, reject) => {
    channel
      .join()
      .receive("ok", (resp: unknown) => {
        const r = resp as Record<string, unknown> | undefined;
        if (r?.connectionId) {
          channel.__connectionId = String(r.connectionId);
        }
        channelJoinPromises.delete(channelKey);
        resolve(channel);
      })
      .receive("error", (resp) => {
        if (channels.get(channelKey) === channel) {
          channels.delete(channelKey);
          channelDocumentIds.delete(channelKey);
          channelScopes.delete(channelKey);
        }
        channelJoinPromises.delete(channelKey);
        reject(createPhoenixJoinError(resp));
      })
      .receive("timeout", () => {
        if (channels.get(channelKey) === channel) {
          channels.delete(channelKey);
          channelDocumentIds.delete(channelKey);
          channelScopes.delete(channelKey);
        }
        channelJoinPromises.delete(channelKey);
        recordAuthTransportNetworkFailure();
        reject(new PhoenixChannelTransportError("join_timeout", "Channel join timed out"));
      });
  });
  channelJoinPromises.set(channelKey, joinPromise);
  return joinPromise;
}

export async function joinTemporaryDocument(
  documentId: string,
  params: Record<string, unknown>,
  callbacks: DocumentChannelCallbacks,
  scope?: "user" | "share",
): Promise<TemporaryDocumentChannelHandle> {
  await ensurePhoenixWsToken(scope);

  const tempSocket = createTemporaryPhoenixSocket(scope);

  const channel = tempSocket.channel(`document:${documentId}`, params);
  configureDocumentChannel(tempSocket, channel, callbacks);

  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    leavePhoenixChannel(channel);
    tempSocket.disconnect();
  };

  return new Promise<TemporaryDocumentChannelHandle>((resolve, reject) => {
    channel
      .join()
      .receive("ok", () => {
        resolve({ channel, dispose });
      })
      .receive("error", (resp) => {
        dispose();
        reject(createPhoenixJoinError(resp));
      })
      .receive("timeout", () => {
        dispose();
        recordAuthTransportNetworkFailure();
        reject(new PhoenixChannelTransportError("join_timeout", "Channel join timed out"));
      });
  });
}

export function pushUpdate(
  documentId: string,
  payload: Record<string, unknown>,
  onReject?: (resp: unknown) => void,
  channelKey = documentId,
): boolean {
  const channel = channels.get(channelKey);
  const channelState = channel ? getChannelState(channel) : "missing";
  if (!channel || channelState !== "joined") {
    console.warn(`[ws] pushUpdate dropped: channel=${channelState}`);
    return false;
  }
  const push = channel.push("update", payload);
  if (onReject) {
    push.receive("error", onReject).receive("timeout", () => onReject("timeout"));
  }
  return true;
}
export function pushSnapshot(
  documentId: string,
  payload: Record<string, unknown>,
  onReject?: (resp: unknown) => void,
  channelKey = documentId,
): boolean {
  const channel = channels.get(channelKey);
  if (!channel || getChannelState(channel) !== "joined") return false;
  const push = channel.push("snapshot", payload);
  if (onReject) {
    push.receive("error", onReject).receive("timeout", () => onReject("timeout"));
  }
  return true;
}
export function pushEphemeral(
  documentId: string,
  payload: Record<string, unknown>,
  channelKey = documentId,
): boolean {
  const channel = channels.get(channelKey);
  if (!channel || getChannelState(channel) !== "joined") return false;
  channel.push("ephemeral", payload);
  return true;
}
export async function rejoinDocument(
  documentId: string,
  params: Record<string, unknown>,
  callbacks: DocumentChannelCallbacks,
  channelKey = documentId,
  scope?: "user" | "share",
): Promise<Channel> {
  const existing = channels.get(channelKey);
  if (existing) {
    // Remove socket state change refs before leave to prevent onClose from firing.
    leavePhoenixChannel(existing);
    channels.delete(channelKey);
    channelDocumentIds.delete(channelKey);
    channelScopes.delete(channelKey);
    channelJoinPromises.delete(channelKey);
  }
  return joinDocument(documentId, params, callbacks, channelKey, scope);
}
export function leaveDocument(documentId: string, channelKey = documentId): void {
  const channel = channels.get(channelKey);
  if (!channel) return;
  leavePhoenixChannel(channel);
  channels.delete(channelKey);
  channelDocumentIds.delete(channelKey);
  channelScopes.delete(channelKey);
  channelJoinPromises.delete(channelKey);
}

export function resetPhoenixConnection(scope?: "user" | "share"): void {
  for (const [channelKey, channel] of channels) {
    if (scope && channelScopes.get(channelKey) !== scope) continue;
    leavePhoenixChannel(channel);
    channels.delete(channelKey);
    channelDocumentIds.delete(channelKey);
    channelScopes.delete(channelKey);
    channelJoinPromises.delete(channelKey);
  }

  resetPhoenixSocketState(scope);
}
