import { Socket, Channel } from "phoenix";
import { authApi } from "@/shared/api/auth";

// Singleton Socket instance (authenticates via ws-token, all channels multiplex)
let socket: Socket | null = null;
let cachedWsToken: string | null = null;
const channels = new Map<string, Channel>();

async function refreshWsToken(): Promise<void> {
  const result = await authApi.wsToken();
  cachedWsToken = result.token;
}

function getOrCreateSocket(): Socket {
  if (socket) return socket;

  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${location.host}/api/socket`;

  socket = new Socket(url, {
    params: () => ({ token: cachedWsToken }),
    reconnectAfterMs: (tries: number) => Math.min(100 * Math.pow(1.8, tries), 30_000),
  });

  // Refresh token on disconnect/error so reconnect uses a fresh token
  socket.onError(() => {
    refreshWsToken().catch(() => {});
  });
  socket.onClose(() => {
    refreshWsToken().catch(() => {});
  });

  socket.connect();
  return socket;
}

export interface DocumentChannelCallbacks {
  onDocument: (payload: Record<string, unknown>) => void;
  onUpdate: (payload: Record<string, unknown>) => void;
  onSnapshot: (payload: Record<string, unknown>) => void;
  onUpdateSaved: (payload: Record<string, unknown>) => void;
  onUpdateSaveFailed: (payload: Record<string, unknown>) => void;
  onSnapshotSaved: (payload: Record<string, unknown>) => void;
  onSnapshotSaveFailed: (payload: Record<string, unknown>) => void;
  onEphemeralMessage: (payload: Record<string, unknown>) => void;
  onPeerLeft: (payload: Record<string, unknown>) => void;
  onUnauthorized: () => void;
  onError: (reason: unknown) => void;
  onClose: () => void;
}

export async function joinDocument(
  documentId: string,
  params: Record<string, unknown>,
  callbacks: DocumentChannelCallbacks,
): Promise<Channel> {
  if (!socket) {
    await refreshWsToken();
  }
  const sock = getOrCreateSocket();
  const topic = `document:${documentId}`;

  const existing = channels.get(documentId);
  if (existing && existing.state === "joined") {
    return Promise.resolve(existing);
  }

  const channel = sock.channel(topic, params);

  // Disable Phoenix auto-rejoin BEFORE join(): PoP challenge is consumed on
  // first join, so auto-rejoin with stale params always fails.
  // 1. Remove socket.onOpen/onError refs that trigger channel.rejoin()
  const sockAny = sock as any;
  const chanAny = channel as any;
  const stateChangeRefs = chanAny.stateChangeRefs as number[];
  if (stateChangeRefs) {
    for (const ref of stateChangeRefs) {
      sockAny.off([ref]);
    }
    stateChangeRefs.length = 0;
  }
  // 2. Neuter the rejoinTimer so error/timeout handlers can't schedule retries
  const rejoinTimer = chanAny.rejoinTimer;
  if (rejoinTimer) {
    rejoinTimer.reset();
    rejoinTimer.scheduleTimeout = () => {};
  }
  // 3. Notify onClose when socket disconnects so document-sync can reconnect
  stateChangeRefs.push(
    sockAny.onClose(() => {
      if (channel.state === "joined") {
        chanAny.state = "closed";
        callbacks.onClose();
      }
    }),
  );

  channel.on("document", (payload) => callbacks.onDocument(payload));
  channel.on("update", (payload) => callbacks.onUpdate(payload));
  channel.on("snapshot", (payload) => callbacks.onSnapshot(payload));
  channel.on("update-saved", (payload) => callbacks.onUpdateSaved(payload));
  channel.on("update-save-failed", (payload) => callbacks.onUpdateSaveFailed(payload));
  channel.on("snapshot-saved", (payload) => callbacks.onSnapshotSaved(payload));
  channel.on("snapshot-save-failed", (payload) => callbacks.onSnapshotSaveFailed(payload));
  channel.on("ephemeral-message", (payload) => callbacks.onEphemeralMessage(payload));
  channel.on("peer-left", (payload) => callbacks.onPeerLeft(payload));
  channel.on("connection-cap-evict", () => callbacks.onError("connection_cap_evict"));
  channel.on("unauthorized", () => callbacks.onUnauthorized());
  channel.on("document-not-found", () => callbacks.onError("document_not_found"));
  channel.on("document-error", () => callbacks.onError("document_error"));

  channel.onError((reason) => callbacks.onError(reason));
  channel.onClose(() => callbacks.onClose());

  channels.set(documentId, channel);

  return new Promise<Channel>((resolve, reject) => {
    channel
      .join()
      .receive("ok", (resp: unknown) => {
        const r = resp as Record<string, unknown> | undefined;
        if (r?.connectionId) {
          (channel as any).__connectionId = r.connectionId;
        }
        resolve(channel);
      })
      .receive("error", (resp) => {
        channels.delete(documentId);
        const err = new Error(`Channel join failed: ${JSON.stringify(resp)}`);
        (err as any).joinErrorResp = resp;
        reject(err);
      })
      .receive("timeout", () => {
        channels.delete(documentId);
        reject(new Error("Channel join timed out"));
      });
  });
}

export function pushUpdate(
  documentId: string,
  payload: Record<string, unknown>,
  onReject?: (resp: unknown) => void,
): void {
  const channel = channels.get(documentId);
  if (!channel || channel.state !== "joined") {
    console.warn(`[ws] pushUpdate dropped: channel=${channel?.state ?? "missing"}`);
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
  if (!channel || channel.state !== "joined") return;
  const push = channel.push("snapshot", payload);
  if (onReject) {
    push.receive("error", onReject).receive("timeout", () => onReject("timeout"));
  }
}

export function pushEphemeral(documentId: string, payload: Record<string, unknown>): boolean {
  const channel = channels.get(documentId);
  if (!channel || channel.state !== "joined") return false;
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
    const refs = (existing as any).stateChangeRefs as number[];
    if (refs) {
      const sockAny = (existing as any).socket;
      for (const ref of refs) {
        sockAny?.off?.([ref]);
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
  // Release socket-level stateChangeRefs to prevent listener leak
  const refs = (channel as any).stateChangeRefs as number[];
  if (refs) {
    const sockAny = (channel as any).socket;
    for (const ref of refs) {
      sockAny?.off?.([ref]);
    }
    refs.length = 0;
  }
  channel.leave();
  channels.delete(documentId);
}

export function getChannel(documentId: string): Channel | null {
  return channels.get(documentId) ?? null;
}

export function disconnectSocket(): void {
  if (!socket) return;
  for (const [id, channel] of channels) {
    channel.leave();
    channels.delete(id);
  }
  socket.disconnect();
  socket = null;
}
