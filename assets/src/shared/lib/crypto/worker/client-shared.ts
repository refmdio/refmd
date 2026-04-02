export interface CryptoWorkerClientMethodContext {
  send(type: string, payload: unknown): Promise<unknown>;
}
