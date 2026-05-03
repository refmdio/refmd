import {
  handleCacheDek,
  handleDecryptContent,
  handleDecryptOfflineCache,
  handleDecryptOfflinePending,
  handleDecryptTitle,
  handleDecryptTitleBatch,
  handleEncryptContent,
  handleEncryptOfflineCache,
  handleEncryptOfflinePending,
  handleEncryptTitle,
  handleEvictDek,
  handleGenerateDek,
  handleHasDek,
  handleHasDekBatch,
  handleUnwrapDek,
  handleUnwrapDekFromOffline,
  handleWrapDek,
  handleWrapDekForShare,
  handleWrapDekForOffline,
} from "../dek";
import { withCryptoOperationError } from "../utils";
import type { RequestHandlerTable } from "./shared";

export const documentRequestHandlers = {
  "cache-dek": (state, payload) => handleCacheDek(state, payload),
  "decrypt-content": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleDecryptContent(state, payload)),
  "decrypt-offline-cache": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleDecryptOfflineCache(state, payload)),
  "decrypt-offline-pending": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleDecryptOfflinePending(state, payload),
    ),
  "decrypt-snapshot": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleDecryptContent(state, payload)),
  "decrypt-title": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleDecryptTitle(state, payload)),
  "decrypt-title-batch": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleDecryptTitleBatch(state, payload)),
  "encrypt-content": (state, payload) => handleEncryptContent(state, payload),
  "encrypt-offline-cache": (state, payload) => handleEncryptOfflineCache(state, payload),
  "encrypt-offline-pending": (state, payload) => handleEncryptOfflinePending(state, payload),
  "encrypt-snapshot": (state, payload) => handleEncryptContent(state, payload),
  "encrypt-title": (state, payload) => handleEncryptTitle(state, payload),
  "evict-dek": (state, payload) => handleEvictDek(state, payload),
  "generate-dek": (state, payload) => handleGenerateDek(state, payload),
  "has-dek": (state, payload) => handleHasDek(state, payload),
  "has-dek-batch": (state, payload) => handleHasDekBatch(state, payload),
  "unwrap-dek": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapDek(state, payload)),
  "unwrap-dek-from-offline": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapDekFromOffline(state, payload)),
  "wrap-dek": (state, payload) => handleWrapDek(state, payload),
  "wrap-dek-for-share": (state, payload) => handleWrapDekForShare(state, payload),
  "wrap-dek-for-offline": (state, payload) => handleWrapDekForOffline(state, payload),
} satisfies RequestHandlerTable;
