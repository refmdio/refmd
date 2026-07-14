export type CryptoErrorCode =
  | "not_initialized"
  | "already_initialized"
  | "rate_limited"
  | "decryption_failed"
  | "signature_failed"
  | "invalid_key"
  | "invalid_payload"
  | "key_not_found"
  | "key_expired"
  | "tofu_hard_fail"
  | "internal_error";

export interface CryptoError {
  code: CryptoErrorCode;
  message: string;
}
