declare module "phoenix" {
  export type ChannelState = "closed" | "errored" | "joined" | "joining" | "leaving";

  export interface RejoinTimer {
    reset(): void;
    scheduleTimeout: () => void;
  }

  export class Socket {
    constructor(endPoint: string, opts?: Record<string, unknown>);
    connect(): void;
    disconnect(callback?: () => void, code?: number, reason?: string): void;
    channel(topic: string, chanParams?: Record<string, unknown>): Channel;
    onOpen(callback: () => void): number;
    onClose(callback: () => void): number;
    onError(callback: (error: unknown) => void): number;
    off(refs: number[]): void;
    isConnected(): boolean;
  }

  export class Channel {
    state: ChannelState;
    socket: Socket;
    stateChangeRefs: number[];
    rejoinTimer?: RejoinTimer;
    __connectionId?: string;
    join(timeout?: number): Push;
    leave(timeout?: number): Push;
    push(event: string, payload: Record<string, unknown>, timeout?: number): Push;
    on<TPayload extends Record<string, unknown>>(
      event: string,
      callback: (payload: TPayload) => void,
    ): number;
    off(event: string, ref?: number): void;
    onError(callback: (reason: unknown) => void): void;
    onClose(callback: () => void): void;
  }

  export class Push {
    receive(status: string, callback: (response: unknown) => void): Push;
  }
}
