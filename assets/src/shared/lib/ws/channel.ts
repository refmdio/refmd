import type { Channel, Socket } from "phoenix";

export interface PhoenixJoinErrorResponse {
  reason?: string;
  [key: string]: unknown;
}

export interface PhoenixJoinError extends Error {
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

export function isPhoenixJoinError(error: unknown): error is PhoenixJoinError {
  return error instanceof Error && "joinErrorResp" in error;
}

export function createPhoenixJoinError(resp: unknown): PhoenixJoinError {
  const joinErrorResp =
    typeof resp === "object" && resp !== null ? (resp as PhoenixJoinErrorResponse) : undefined;
  return Object.assign(new Error(`Channel join failed: ${JSON.stringify(resp)}`), {
    joinErrorResp,
  });
}

export function getPhoenixJoinErrorReason(errorOrResp: unknown): string | null {
  const resp = isPhoenixJoinError(errorOrResp)
    ? errorOrResp.joinErrorResp
    : typeof errorOrResp === "object" && errorOrResp !== null
      ? (errorOrResp as PhoenixJoinErrorResponse)
      : undefined;

  return typeof resp?.reason === "string" ? resp.reason : null;
}

export function clearChannelStateChangeRefs(channel: Channel): void {
  const refs = channel.stateChangeRefs;
  if (!refs) return;

  const channelSocket = channel.socket;
  for (const ref of refs) {
    channelSocket.off([ref]);
  }
  refs.length = 0;
}

export function disableChannelAutoRejoin(channel: Channel): void {
  clearChannelStateChangeRefs(channel);

  const rejoinTimer = channel.rejoinTimer;
  if (rejoinTimer) {
    rejoinTimer.reset();
    rejoinTimer.scheduleTimeout = () => {};
  }
}

export function notifyChannelClosedOnSocketClose(
  sock: Socket,
  channel: Channel,
  onClose: () => void,
): void {
  channel.stateChangeRefs?.push(
    sock.onClose(() => {
      if (channel.state === "joined") {
        channel.state = "closed";
        onClose();
      }
    }),
  );
}

export function leavePhoenixChannel(channel: Channel): void {
  clearChannelStateChangeRefs(channel);
  channel.leave();
}
