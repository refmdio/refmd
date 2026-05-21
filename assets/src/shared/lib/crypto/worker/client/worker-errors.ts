import type { CryptoErrorCode } from "../types";

export class CryptoWorkerError extends Error {
  readonly code: CryptoErrorCode;
  readonly requestType?: string;

  constructor(code: CryptoErrorCode, message: string, requestType?: string) {
    super(message);
    this.name = "CryptoWorkerError";
    this.code = code;
    this.requestType = requestType;
  }
}

export function isTofuHardFail(error: unknown): error is CryptoWorkerError {
  return error instanceof CryptoWorkerError && error.code === "tofu_hard_fail";
}
