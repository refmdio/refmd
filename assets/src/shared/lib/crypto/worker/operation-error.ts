import type { CryptoErrorCode } from "./types";

export class CryptoOperationError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.name = "CryptoOperationError";
    this.code = code;
  }
}
