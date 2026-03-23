declare module "phoenix" {
  export class Socket {
    constructor(endPoint: string, opts?: Record<string, unknown>);
    connect(): void;
    disconnect(callback?: () => void, code?: number, reason?: string): void;
    channel(topic: string, chanParams?: Record<string, unknown>): Channel;
    onOpen(callback: () => void): void;
    onClose(callback: () => void): void;
    onError(callback: (error: unknown) => void): void;
    isConnected(): boolean;
  }

  export class Channel {
    state: string;
    join(timeout?: number): Push;
    leave(timeout?: number): Push;
    push(event: string, payload: Record<string, unknown>, timeout?: number): Push;
    on(event: string, callback: (payload: Record<string, unknown>) => void): number;
    off(event: string, ref?: number): void;
    onError(callback: (reason: unknown) => void): void;
    onClose(callback: () => void): void;
  }

  export class Push {
    receive(status: string, callback: (response: unknown) => void): Push;
  }
}
