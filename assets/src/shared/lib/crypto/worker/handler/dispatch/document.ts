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
  handleFetchMountedShareDocumentBootstrap,
  handleFetchMountedShareFolderBootstrap,
  handleFetchShareDocumentBootstrap,
  handleFetchShareFolderBootstrap,
  handleGenerateDek,
  handleClearShareSecrets,
  handleCloneShareDekEncryptionKey,
  handleHasDek,
  handleHasDekBatch,
  handleHasShareDekEncryptionKey,
  handleDeleteDekForOffline,
  handlePrepareManagedShareSecrets,
  handleLoadOfflineDekMetadata,
  handleRestoreShareSecretsFromDsk,
  handlePrepareOpenShareSecrets,
  handlePreparePasswordShareChallenge,
  handlePreparePasswordShareSecrets,
  handleUnwrapDek,
  handleUnwrapShareDek,
  handleRestoreDekFromOffline,
  handleWrapDek,
  handleWrapDekForShare,
  handleStoreDekForOffline,
  handlePersistMountedShareSecretsWithDsk,
  handleWrapPreparedShareDek,
  handlePersistShareSecretsWithDsk,
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
  "unwrap-share-dek": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapShareDek(state, payload)),
  "fetch-share-document-bootstrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleFetchShareDocumentBootstrap(state, payload),
    ),
  "fetch-share-folder-bootstrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleFetchShareFolderBootstrap(state, payload),
    ),
  "fetch-mounted-share-document-bootstrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleFetchMountedShareDocumentBootstrap(state, payload),
    ),
  "fetch-mounted-share-folder-bootstrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleFetchMountedShareFolderBootstrap(state, payload),
    ),
  "prepare-managed-share-secrets": (state, payload) =>
    handlePrepareManagedShareSecrets(state, payload),
  "wrap-prepared-share-dek": (state, payload) => handleWrapPreparedShareDek(state, payload),
  "prepare-open-share-secrets": (state, payload) => handlePrepareOpenShareSecrets(state, payload),
  "prepare-password-share-secrets": (state, payload) =>
    handlePreparePasswordShareSecrets(state, payload),
  "prepare-password-share-challenge": (state, payload) =>
    handlePreparePasswordShareChallenge(state, payload),
  "restore-share-secrets-from-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleRestoreShareSecretsFromDsk(state, payload),
    ),
  "has-share-dek-encryption-key": (state, payload) =>
    handleHasShareDekEncryptionKey(state, payload),
  "clone-share-dek-encryption-key": (state, payload) =>
    handleCloneShareDekEncryptionKey(state, payload),
  "clear-share-secrets": (state, payload) => handleClearShareSecrets(state, payload),
  "persist-share-secrets-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handlePersistShareSecretsWithDsk(state, payload),
    ),
  "persist-mounted-share-secrets-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handlePersistMountedShareSecretsWithDsk(state, payload),
    ),
  "restore-dek-from-offline": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleRestoreDekFromOffline(state, payload),
    ),
  "load-offline-dek-metadata": (_state, payload) => handleLoadOfflineDekMetadata(payload),
  "delete-dek-for-offline": (_state, payload) => handleDeleteDekForOffline(payload),
  "wrap-dek": (state, payload) => handleWrapDek(state, payload),
  "wrap-dek-for-share": (state, payload) => handleWrapDekForShare(state, payload),
  "store-dek-for-offline": (state, payload) => handleStoreDekForOffline(state, payload),
} satisfies RequestHandlerTable;
