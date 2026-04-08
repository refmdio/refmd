import type { WorkerKeyState } from "../../state";
import type { CryptoRequest } from "../../types";
import type { HandlerPayload } from "../utils";

export type RequestHandler = (
  state: WorkerKeyState,
  payload: HandlerPayload,
) => Promise<unknown> | unknown;

export type RequestHandlerTable = Partial<Record<CryptoRequest["type"], RequestHandler>>;
