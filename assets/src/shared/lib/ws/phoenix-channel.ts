import { Socket, Channel } from "phoenix";

// Singleton Socket instance (authenticates via HttpOnly cookie, all channels multiplex)
let socket: Socket | null = null;
const channels = new Map<string, Channel>();

function getOrCreateSocket(): Socket {
  if (socket) return socket;

  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${location.host}/api/socket`;

  socket = new Socket(url, {
    reconnectAfterMs: (tries: number) => Math.min(100 * Math.pow(1.8, tries), 30_000),
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
  onUnauthorized: () => void;
  onError: (reason: unknown) => void;
  onClose: () => void;
}

export function joinDocument(
  documentId: string,
  params: Record<string, unknown>,
  callbacks: DocumentChannelCallbacks,
): Promise<Channel> {
  const sock = getOrCreateSocket();
  const topic = `document:${documentId}`;

  const existing = channels.get(documentId);
  if (existing && existing.state === "joined") {
    return Promise.resolve(existing);
  }

  const channel = sock.channel(topic, params);

  channel.on("document", (payload) => callbacks.onDocument(payload));
  channel.on("update", (payload) => callbacks.onUpdate(payload));
  channel.on("snapshot", (payload) => callbacks.onSnapshot(payload));
  channel.on("update-saved", (payload) => callbacks.onUpdateSaved(payload));
  channel.on("update-save-failed", (payload) => callbacks.onUpdateSaveFailed(payload));
  channel.on("snapshot-saved", (payload) => callbacks.onSnapshotSaved(payload));
  channel.on("snapshot-save-failed", (payload) => callbacks.onSnapshotSaveFailed(payload));
  channel.on("ephemeral-message", (payload) => callbacks.onEphemeralMessage(payload));
  channel.on("unauthorized", () => callbacks.onUnauthorized());
  channel.on("document-not-found", () => callbacks.onError("document_not_found"));
  channel.on("document-error", () => callbacks.onError("document_error"));

  channel.onError((reason) => callbacks.onError(reason));
  channel.onClose(() => callbacks.onClose());

  channels.set(documentId, channel);

  return new Promise<Channel>((resolve, reject) => {
    channel
      .join()
      .receive("ok", () => resolve(channel))
      .receive("error", (resp) => {
        channels.delete(documentId);
        reject(new Error(`Channel join failed: ${JSON.stringify(resp)}`));
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
  if (!channel || channel.state !== "joined") return;
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

export function pushEphemeral(documentId: string, payload: Record<string, unknown>): void {
  const channel = channels.get(documentId);
  if (!channel || channel.state !== "joined") return;
  channel.push("ephemeral", payload);
}

export function leaveDocument(documentId: string): void {
  const channel = channels.get(documentId);
  if (!channel) return;
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
