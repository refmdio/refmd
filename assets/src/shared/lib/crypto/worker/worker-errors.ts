import type { CryptoErrorCode } from "./types";

export class CryptoWorkerError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.name = "CryptoWorkerError";
    this.code = code;
  }
}

export function isTofuHardFail(error: unknown): error is CryptoWorkerError {
  return error instanceof CryptoWorkerError && error.code === "tofu_hard_fail";
}
