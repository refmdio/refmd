import type { CryptoRequest } from "../types";
import type { WorkerKeyState } from "../state";
import { requestHandlers } from "./dispatch";
import type { HandlerPayload } from "./utils";

export async function handleRequest(
  state: WorkerKeyState,
  request: CryptoRequest,
): Promise<unknown> {
  const handler = requestHandlers[request.type];
  if (!handler) {
    throw new Error(`Unknown request type: ${request.type}`);
  }
  return handler(state, request.payload as HandlerPayload);
}
