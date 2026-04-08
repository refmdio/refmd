import { Socket, Channel } from "phoenix";
import { authApi } from "@/shared/api/auth";
import { setWsConnected } from "@/shared/lib/offline/offline-state";
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
} from "./document-payloads";

// Singleton Socket instance (authenticates via ws-token, all channels multiplex)
let socket: Socket | null = null;
let cachedWsToken: string | null = null;
const channels = new Map<string, Channel>();
interface PhoenixJoinErrorResponse {
  reason?: string;
  [key: string]: unknown;
}
interface PhoenixJoinError extends Error {
  joinErrorResp?: PhoenixJoinErrorResponse;
}
export class PhoenixChannelTransportError extends Error {
  readonly code: "join_timeout" | "disconnected_before_document";
  constructor(code: "join_timeout" | "disconnected_before_document", message: string) {
    super(message);
    this.name = "PhoenixChannelTransportError";
    this.code = code;
  }
}
async function refreshWsToken(): Promise<void> {
  const result = await authApi.wsToken();
  cachedWsToken = result.token;
}

function getSocketUrl(): string {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${location.host}/api/socket`;
}

function getOrCreateSocket(): Socket {
  if (socket) {
    if (!socket.isConnected()) {
      socket.connect();
    }
    return socket;
  }
  const activeSocket = new Socket(getSocketUrl(), {
    params: () => ({ token: cachedWsToken }),
    reconnectAfterMs: (tries: number) => Math.min(100 * Math.pow(1.8, tries), 30000),
  });
  socket = activeSocket;
  activeSocket.onOpen(() => {
    if (socket !== activeSocket) return;
    setWsConnected(true);
  });
  // Refresh token on disconnect/error so reconnect uses a fresh token
  activeSocket.onError(() => {
    if (socket !== activeSocket) return;
    setWsConnected(false);
    refreshWsToken().catch(() => {});
  });
  activeSocket.onClose(() => {
    if (socket !== activeSocket) return;
    setWsConnected(false);
    refreshWsToken().catch(() => {});
  });
  activeSocket.connect();
  return activeSocket;
}
export function getChannelState(channel: Channel): string {
  return channel.state;
}

export function hasTrackedDocumentChannel(documentId: string): boolean {
  return channels.has(documentId);
}

export function isSocketConnected(target: Socket): boolean;
export function isSocketConnected(): boolean;
export function isSocketConnected(target?: Socket): boolean {
  return target !== undefined ? target.isConnected() : socket !== null && socket.isConnected();
}
export function isPhoenixJoinError(error: unknown): error is PhoenixJoinError {
  return error instanceof Error && "joinErrorResp" in error;
}
function createPhoenixJoinError(resp: unknown): PhoenixJoinError {
  const joinErrorResp =
    typeof resp === "object" && resp !== null ? (resp as PhoenixJoinErrorResponse) : undefined;
  return Object.assign(new Error(`Channel join failed: ${JSON.stringify(resp)}`), {
    joinErrorResp,
  });
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
  onUnauthorized: () => void;
  onError: (reason: unknown) => void;
  onClose: () => void;
}

export interface TemporaryDocumentChannelHandle {
  channel: Channel;
  dispose: () => void;
}

function clearChannelStateChangeRefs(channel: Channel): void {
  const refs = channel.stateChangeRefs;
  if (!refs) return;

  const channelSocket = channel.socket;
  for (const ref of refs) {
    channelSocket.off([ref]);
  }
  refs.length = 0;
}

function configureDocumentChannel(
  sock: Socket,
  channel: Channel,
  callbacks: DocumentChannelCallbacks,
): void {
  const stateChangeRefs = channel.stateChangeRefs;
  const rejoinTimer = channel.rejoinTimer;

  // Disable Phoenix auto-rejoin BEFORE join(): PoP challenge is consumed on
  // first join, so auto-rejoin with stale params always fails.
  if (stateChangeRefs) {
    for (const ref of stateChangeRefs) {
      sock.off([ref]);
    }
    stateChangeRefs.length = 0;
  }

  if (rejoinTimer) {
    rejoinTimer.reset();
    rejoinTimer.scheduleTimeout = () => {};
  }

  stateChangeRefs?.push(
    sock.onClose(() => {
      if (getChannelState(channel) === "joined") {
        channel.state = "closed";
        callbacks.onClose();
      }
    }),
  );

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
): Promise<Channel> {
  if (!socket || !socket.isConnected()) {
    await refreshWsToken();
  }
  const sock = getOrCreateSocket();
  const topic = `document:${documentId}`;
  const existing = channels.get(documentId);
  if (existing && getChannelState(existing) === "joined") {
    return Promise.resolve(existing);
  }
  const channel = sock.channel(topic, params);
  configureDocumentChannel(sock, channel, callbacks);
  channels.set(documentId, channel);
  return new Promise<Channel>((resolve, reject) => {
    channel
      .join()
      .receive("ok", (resp: unknown) => {
        const r = resp as Record<string, unknown> | undefined;
        if (r?.connectionId) {
          channel.__connectionId = String(r.connectionId);
        }
        resolve(channel);
      })
      .receive("error", (resp) => {
        channels.delete(documentId);
        reject(createPhoenixJoinError(resp));
      })
      .receive("timeout", () => {
        channels.delete(documentId);
        reject(new PhoenixChannelTransportError("join_timeout", "Channel join timed out"));
      });
  });
}

export async function joinTemporaryDocument(
  documentId: string,
  params: Record<string, unknown>,
  callbacks: DocumentChannelCallbacks,
): Promise<TemporaryDocumentChannelHandle> {
  if (!cachedWsToken) {
    await refreshWsToken();
  }

  const tempSocket = new Socket(getSocketUrl(), {
    params: () => ({ token: cachedWsToken }),
    reconnectAfterMs: () => Infinity,
  });
  tempSocket.connect();

  const channel = tempSocket.channel(`document:${documentId}`, params);
  configureDocumentChannel(tempSocket, channel, callbacks);

  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    clearChannelStateChangeRefs(channel);
    channel.leave();
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
        reject(new PhoenixChannelTransportError("join_timeout", "Channel join timed out"));
      });
  });
}

export function pushUpdate(
  documentId: string,
  payload: Record<string, unknown>,
  onReject?: (resp: unknown) => void,
): void {
  const channel = channels.get(documentId);
  const channelState = channel ? getChannelState(channel) : "missing";
  if (!channel || channelState !== "joined") {
    console.warn(`[ws] pushUpdate dropped: channel=${channelState}`);
    return;
  }
  const push = channel.push("update", payload);
  if (onReject) {
    push.receive("error", onReject).receive("timeout", () => onReject("timeout"));
  }
}
export function pushSnapshot(
  documentId: string,
  payload: Record<string, unknown>,
  onReject?: (resp: unknown) => void,
): void {
  const channel = channels.get(documentId);
  if (!channel || getChannelState(channel) !== "joined") return;
  const push = channel.push("snapshot", payload);
  if (onReject) {
    push.receive("error", onReject).receive("timeout", () => onReject("timeout"));
  }
}
export function pushEphemeral(documentId: string, payload: Record<string, unknown>): boolean {
  const channel = channels.get(documentId);
  if (!channel || getChannelState(channel) !== "joined") return false;
  channel.push("ephemeral", payload);
  return true;
}
export async function rejoinDocument(
  documentId: string,
  params: Record<string, unknown>,
  callbacks: DocumentChannelCallbacks,
): Promise<Channel> {
  const existing = channels.get(documentId);
  if (existing) {
    // Remove socket state change refs before leave to prevent onClose from firing
    const refs = existing.stateChangeRefs;
    if (refs) {
      const existingSocket = existing.socket;
      for (const ref of refs) {
        existingSocket.off([ref]);
      }
      refs.length = 0;
    }
    existing.leave();
    channels.delete(documentId);
  }
  return joinDocument(documentId, params, callbacks);
}
export function leaveDocument(documentId: string): void {
  const channel = channels.get(documentId);
  if (!channel) return;
  clearChannelStateChangeRefs(channel);
  channel.leave();
  channels.delete(documentId);
}

export function resetPhoenixConnection(): void {
  const activeSocket = socket;
  socket = null;
  for (const [documentId, channel] of channels) {
    const refs = channel.stateChangeRefs;
    if (refs) {
      const channelSocket = channel.socket;
      for (const ref of refs) {
        channelSocket.off([ref]);
      }
      refs.length = 0;
    }
    channel.leave();
    channels.delete(documentId);
  }

  if (activeSocket) {
    activeSocket.disconnect();
  }

  cachedWsToken = null;
  setWsConnected(true);
}
