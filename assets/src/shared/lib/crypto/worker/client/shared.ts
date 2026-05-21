import type { CryptoRequestType } from "../types/request";

export const workerSend: unique symbol = Symbol("worker-send");

export interface CryptoWorkerClientMethodContext {
  [workerSend](type: CryptoRequestType, payload: unknown): Promise<unknown>;
}
